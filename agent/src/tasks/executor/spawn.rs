//! The one place in the task module that starts a process (P3-A03, threat model section 8).
//!
//! **What can be run.** A [`Program`]: an absolute executable path and fixed arguments, both
//! `&'static str` written in the agent's code, and at most one [`ValidatedArg`] placed after `--`.
//! A `ValidatedArg` can only be made by a validator in this file (today: a service unit name, by the
//! catalog's pattern), so a task parameter can fill one argument position, never the executable or
//! an option. The agent's own helper calls (`systemd-run`, `systemctl`, `journalctl` for transient
//! units, [`super::unit`]) use [`Generated`] values, made here from typed input (a task id that is a
//! UUID, a step number, a number of seconds, an invocation id of 32 hex digits). Nothing else reaches
//! [`std::process::Command`], and no shell is ever run: `scripts/check-task-spawns.sh` fails CI if
//! `Command`, `.arg(`, or `.args(` appear anywhere else in `src/tasks`, or a shell anywhere.
//!
//! **How it runs.** With the environment cleared and only [`ENVIRONMENT`] set, working directory
//! `/`, standard input from `/dev/null`, standard output and standard error into one pipe read into
//! a bounded [`Capture`], and in a process group of its own. A watchdog thread ends the whole group
//! when the deadline passes, when the server cancels an interruptible task, or when the agent stops
//! (an interruptible task at once, any other after [`SHUTDOWN_WAIT`]): `SIGTERM`, a grace period,
//! then `SIGKILL`. Whatever is left in the group when the program exits is killed too. The program
//! is reaped only after the watchdog has finished, so its process group id cannot be reused by an
//! unrelated process while a signal may still be sent to it.

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::output::Capture;
use super::{Control, Stop};
use crate::shutdown::Shutdown;
use crate::tasks::catalog::Privilege;

/// `PATH` for every task process.
pub const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// The whole environment of every task process, and nothing else (FR-3.3, P3-A03).
pub const ENVIRONMENT: &[(&str, &str)] = &[
    ("PATH", PATH),
    ("LANG", "C"),
    ("DEBIAN_FRONTEND", "noninteractive"),
];

/// The working directory of every task process.
pub const WORKING_DIRECTORY: &str = "/";

/// How long a process may take to exit after `SIGTERM` before the group is killed.
pub const TERM_GRACE: Duration = Duration::from_secs(10);

/// How long a task that cannot be interrupted may keep running after the agent is asked to stop,
/// before it is ended like a timed-out one. Below systemd's default stop timeout (90 s), so the
/// agent records the interruption itself before systemd kills it.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(45);

/// How often the watchdog and the waiting thread look at the process.
const TICK: Duration = Duration::from_millis(20);

/// How long to wait for the output pipe to close once the program and its group are gone (a
/// process that left the group could hold it open).
const DRAIN_WAIT: Duration = Duration::from_secs(2);

/// A program a task runs: fixed executable, fixed arguments, and at most one validated operand.
#[derive(Debug, Clone)]
pub struct Program {
    /// Absolute path, written in the agent's code.
    pub path: &'static str,
    /// Fixed arguments, written in the agent's code, before the operand.
    pub args: &'static [&'static str],
    /// The one argument a task parameter may fill, always after `--`.
    pub operand: Option<ValidatedArg>,
    /// What the program needs (`privilege` in the catalog): it runs only for a task type whose
    /// catalog privilege is at least this, and a `package_manager` program runs in a transient
    /// unit outside the agent's sandbox ([`super::unit`]).
    pub privilege: Privilege,
}

/// An argument made from a task parameter by a validator in this file. Its field is private, so no
/// other code can make one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedArg(String);

impl ValidatedArg {
    /// A systemd service unit name as the catalog's `service` parameter allows:
    /// `^[A-Za-z0-9][A-Za-z0-9_.@-]{0,247}\.service$`. Never starts with `-`.
    pub fn service_unit(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(".service")?;
        let mut chars = stem.chars();
        let first = chars.next()?;
        let ok = first.is_ascii_alphanumeric()
            && stem.len() <= 248
            && chars.all(|c| c.is_ascii_alphanumeric() || "_.@-".contains(c));
        ok.then(|| Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An argument the agent makes for its own helper calls, from typed input only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated(String);

impl Generated {
    /// The transient unit of step `step` of task `task_id`: `fleet-agent-task-<id>-<step>.service`.
    /// `None` unless the id is a lower-case UUID. Protected from `restart_service` by the
    /// `fleet-agent*` rule (DEC-15).
    pub fn task_unit(task_id: &str, step: u32) -> Option<Self> {
        crate::tasks::ledger::is_task_id(task_id)
            .then(|| Self(format!("fleet-agent-task-{task_id}-{step}.service")))
    }

    /// `--property=RuntimeMaxSec=<seconds>`.
    pub fn runtime_max(seconds: u64) -> Self {
        Self(format!("--property=RuntimeMaxSec={seconds}"))
    }

    /// The journal match for one run of a unit: `_SYSTEMD_INVOCATION_ID=<32 hex digits>`.
    pub fn invocation_match(invocation: &str) -> Option<Self> {
        (invocation.len() == 32 && invocation.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Self(format!("_SYSTEMD_INVOCATION_ID={invocation}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One argument of a helper call.
#[derive(Debug, Clone, Copy)]
pub enum Arg<'a> {
    Fixed(&'static str),
    Operand(&'a ValidatedArg),
    Generated(&'a Generated),
}

impl Arg<'_> {
    fn as_str(&self) -> &str {
        match self {
            Self::Fixed(s) => s,
            Self::Operand(v) => v.as_str(),
            Self::Generated(g) => g.as_str(),
        }
    }
}

impl Program {
    /// The argument vector: the fixed arguments, then `--` and the operand when there is one.
    pub fn argv(&self) -> Vec<Arg<'_>> {
        let mut argv: Vec<Arg<'_>> = self.args.iter().map(|a| Arg::Fixed(a)).collect();
        if let Some(operand) = &self.operand {
            argv.push(Arg::Fixed("--"));
            argv.push(Arg::Operand(operand));
        }
        argv
    }
}

/// When to stop a running process.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub deadline: Instant,
    /// Whether the server's cancel and the agent's shutdown may stop it at once.
    pub interruptible: bool,
}

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    /// The exit status, if it exited.
    pub code: Option<i32>,
    /// The signal that killed it, if one did.
    pub signal: Option<i32>,
}

impl Exit {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Runs `path` with `args` as described in the module documentation, adding its output to
/// `capture`. `Err` says why it was stopped (and the group was killed), or why it could not start.
pub fn run(
    path: &'static str,
    args: &[Arg<'_>],
    limits: Limits,
    control: &dyn Control,
    capture: &Arc<Mutex<Capture>>,
) -> Result<Exit, Stop> {
    if !path.starts_with('/') {
        return Err(Stop::Failed("agent_error"));
    }
    let (reader, writer) = std::io::pipe().map_err(|_| Stop::Failed("agent_error"))?;
    let writer_err = writer
        .try_clone()
        .map_err(|_| Stop::Failed("agent_error"))?;
    let mut command = Command::new(path);
    command
        .args(args.iter().map(Arg::as_str))
        .env_clear()
        .envs(ENVIRONMENT.iter().copied())
        .current_dir(WORKING_DIRECTORY)
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(writer_err)
        .process_group(0);
    let spawned = command.spawn();
    // The parent's copies of the write end must close, or the pipe never reports end of file.
    drop(command);
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            tracing::error!(program = path, "cannot start a task program: {e}");
            lock(capture).note(&format!("could not start {path}: {e}"));
            return Err(Stop::Failed("agent_error"));
        }
    };
    let pid = child.id() as libc::pid_t;

    let drain = {
        let capture = Arc::clone(capture);
        thread::Builder::new()
            .name("task-output".into())
            .spawn(move || drain(reader, &capture))
    };

    let done = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let (done, cancel) = (Arc::clone(&done), Arc::clone(&cancel));
        let shutdown = control.shutdown().clone();
        thread::Builder::new()
            .name("task-watchdog".into())
            .spawn(move || watch(pid, limits, &done, &cancel, &shutdown))
    };
    let watchdog = match watchdog {
        Ok(handle) => handle,
        Err(_) => {
            // No watchdog, no deadline: do not let it run.
            signal_group(pid, libc::SIGKILL);
            let _ = child.wait();
            return Err(Stop::Failed("agent_error"));
        }
    };

    // Wait for the program to exit without reaping it, asking the server about a cancel meanwhile.
    while !exited(pid) {
        if limits.interruptible && control.cancel_requested() {
            cancel.store(true, Ordering::SeqCst);
        } else if !limits.interruptible {
            // Keep the server informed (progress); a cancel never stops this task (DEC-14).
            control.cancel_requested();
        }
        thread::sleep(TICK);
    }
    done.store(true, Ordering::SeqCst);
    let stopped = watchdog.join().unwrap_or(Some(Stop::Failed("agent_error")));
    // Nothing of the task outlives it: the program is a zombie until reaped, so its group id is
    // still its own.
    signal_group(pid, libc::SIGKILL);
    let status = child.wait();
    if let Ok(handle) = drain {
        let until = Instant::now() + DRAIN_WAIT;
        while !handle.is_finished() && Instant::now() < until {
            thread::sleep(TICK);
        }
    }
    if let Some(stop) = stopped {
        return Err(stop);
    }
    let status = status.map_err(|_| Stop::Failed("agent_error"))?;
    Ok(Exit {
        code: status.code(),
        signal: status.signal(),
    })
}

pub(super) fn lock(capture: &Mutex<Capture>) -> std::sync::MutexGuard<'_, Capture> {
    capture.lock().unwrap_or_else(|e| e.into_inner())
}

/// Reads the pipe to its end into `capture`.
fn drain(mut reader: std::io::PipeReader, capture: &Mutex<Capture>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => lock(capture).push(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

/// The watchdog: ends the group when a limit is reached, and says which.
fn watch(
    pid: libc::pid_t,
    limits: Limits,
    done: &AtomicBool,
    cancel: &AtomicBool,
    shutdown: &Shutdown,
) -> Option<Stop> {
    let mut shutdown_seen: Option<Instant> = None;
    loop {
        if done.load(Ordering::SeqCst) {
            return None;
        }
        let now = Instant::now();
        let why = if now >= limits.deadline {
            Some(Stop::TimedOut)
        } else if cancel.load(Ordering::SeqCst) {
            Some(Stop::Cancelled)
        } else if shutdown.is_requested() {
            let seen = *shutdown_seen.get_or_insert(now);
            (limits.interruptible || now.duration_since(seen) >= SHUTDOWN_WAIT)
                .then_some(Stop::Interrupted)
        } else {
            None
        };
        if let Some(why) = why {
            terminate(pid, done);
            return Some(why);
        }
        thread::sleep(TICK);
    }
}

/// `SIGTERM` to the group, up to [`TERM_GRACE`] for the program to exit, then `SIGKILL`.
fn terminate(pid: libc::pid_t, done: &AtomicBool) {
    signal_group(pid, libc::SIGTERM);
    let until = Instant::now() + TERM_GRACE;
    while !done.load(Ordering::SeqCst) && Instant::now() < until {
        thread::sleep(TICK);
    }
    signal_group(pid, libc::SIGKILL);
}

fn signal_group(pid: libc::pid_t, signal: libc::c_int) {
    // SAFETY: killpg with the group id of a child this process has not reaped; an error (the group
    // is empty) is harmless.
    unsafe {
        libc::killpg(pid, signal);
    }
}

/// Whether the child `pid` has exited, without reaping it.
fn exited(pid: libc::pid_t) -> bool {
    // SAFETY: waitid with WNOWAIT only reads the child's state into a zeroed siginfo_t.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        // An error means there is no such child to wait for: treat it as gone.
        r != 0 || info.si_pid() != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_unit_name_the_catalog_allows_is_an_operand() {
        for good in [
            "nginx.service",
            "postgresql@17-main.service",
            "a.service",
            "x_y.z-1.service",
        ] {
            assert_eq!(ValidatedArg::service_unit(good).unwrap().as_str(), good);
        }
        for bad in [
            "",
            ".service",
            "-x.service",
            "--now.service",
            "nginx",
            "nginx.socket",
            "a b.service",
            "a;b.service",
            "$(x).service",
            "../x.service",
            "ngin\u{202e}x.service",
            "ñ.service",
            &format!("{}.service", "a".repeat(249)),
        ] {
            assert!(ValidatedArg::service_unit(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn generated_arguments_come_only_from_typed_input() {
        let id = "0b5c8a4e-1d6f-4a3b-9c2d-7e8f9a0b1c2d";
        assert_eq!(
            Generated::task_unit(id, 1).unwrap().as_str(),
            "fleet-agent-task-0b5c8a4e-1d6f-4a3b-9c2d-7e8f9a0b1c2d-1.service"
        );
        assert!(Generated::task_unit("--now", 1).is_none());
        assert!(Generated::task_unit("0B5C8A4E-1D6F-4A3B-9C2D-7E8F9A0B1C2D", 1).is_none());
        assert_eq!(
            Generated::runtime_max(3660).as_str(),
            "--property=RuntimeMaxSec=3660"
        );
        assert!(Generated::invocation_match("0123456789abcdef0123456789abcdef").is_some());
        assert!(Generated::invocation_match("0123456789abcdef0123456789abcde").is_none());
        assert!(Generated::invocation_match("0123456789abcdef0123456789abcdeg").is_none());
    }

    #[test]
    fn the_operand_always_follows_the_end_of_options_marker() {
        let program = Program {
            path: "/usr/bin/systemctl",
            args: &["restart"],
            operand: ValidatedArg::service_unit("nginx.service"),
            privilege: Privilege::ServiceManager,
        };
        let argv = program.argv();
        let argv: Vec<&str> = argv.iter().map(Arg::as_str).collect();
        assert_eq!(argv, ["restart", "--", "nginx.service"]);
        let bare = Program {
            operand: None,
            ..program
        };
        let argv = bare.argv();
        let argv: Vec<&str> = argv.iter().map(Arg::as_str).collect();
        assert_eq!(argv, ["restart"]);
    }
}
