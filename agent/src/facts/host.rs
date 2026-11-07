//! The host as the fact readers see it (P2-A01, P2-A02, P2-A03): four operations and nothing else.
//!
//! - [`Host::stat`]: `stat(2)` of a path (mode, owner, group), following symlinks;
//! - [`Host::read`]: a bounded read of a regular file;
//! - [`Host::list`]: the names in a directory, bounded;
//! - [`Host::run`]: one program from a fixed list of absolute paths, with fixed arguments, no shell,
//!   a cleared environment, a time limit, and a bound on the output.
//!
//! Every reader goes through this trait, so a test can give it a fake host that serves fixture files
//! and canned command output and records what was asked. That is how the tests prove that the files
//! the manifest lists as sensitive (`/etc/shadow` and the like) are only ever `stat`ed, never opened
//! (P2-A03), and that no reader runs anything but its own fixed command.
//!
//! # Safety of the real host ([`RealHost`])
//!
//! - **Bounded reads.** A file must be a regular file of at most the size the reader allows
//!   ([`crate::fsx::read_regular`]): it is opened without blocking, so a FIFO or device planted at a
//!   source path is refused at once, and a huge file is refused, not read.
//! - **Time limits.** A filesystem call can hang on a dead network mount. Each runs on its own thread
//!   and is abandoned after [`IO_TIMEOUT`]. An abandoned call cannot be cancelled, so the thread lives
//!   until the call returns; the same operation on the same path is not started again meanwhile
//!   (it fails as still blocked), so a stuck path holds one thread, not one per collection.
//! - **Symlinks** are followed. Debian keeps system files behind links, and the paths read here sit
//!   in directories only root can change. What is read through a link is still only parsed for the
//!   few settings a reader wants; nothing from a file is reported beyond them.
//! - **Secrets.** [`read_file`] refuses the paths in [`is_secret_path`] whatever a reader asks for, a
//!   second line of defence behind the readers themselves never asking. [`RealHost::read`] also
//!   resolves the path (inside the bounded call, so a dead mount cannot hang it) and refuses it when
//!   it *leads to* a secret file, then reads the resolved path: a `pwquality.conf.d/x.conf` linked to
//!   `/etc/shadow` is refused, not opened. A resolved path that is not UTF-8 is refused too.
//! - **Commands** run from absolute paths (never a `PATH` search), with no shell, `stdin` closed, a
//!   cleared environment, and a kill at the time limit or when the output passes its bound.
//! - **Threads.** Every thread is started with `thread::Builder`, so one that cannot start (a task
//!   limit, memory pressure) fails that call with an error instead of panicking the agent.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::fsx::{self, Symlinks};

/// Time limit for one filesystem call.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// What `stat(2)` says about a path: permission bits including the special bits, and the owner ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// `st_mode & 0o7777`.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// A program to run: the first of `programs` (absolute paths) that exists, with `args`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub programs: &'static [&'static str],
    pub args: Vec<String>,
    pub timeout: Duration,
    /// Most bytes of standard output kept; more kills the program.
    pub max_output: usize,
}

impl Command {
    pub fn new(programs: &'static [&'static str], args: &[&str]) -> Self {
        Self {
            programs,
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            timeout: Duration::from_secs(10),
            max_output: 4 * 1024 * 1024,
        }
    }

    /// The command as one line, for logs and tests.
    #[cfg(test)]
    pub fn line(&self) -> String {
        let program = self.programs.first().copied().unwrap_or("");
        std::iter::once(program)
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Why a command gave no output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// None of the program's paths exists.
    NotInstalled(String),
    PermissionDenied(String),
    TimedOut(Duration),
    /// More output than the bound; the program was killed.
    TooMuchOutput(usize),
    /// The collection's overall time budget ran out before the command could start.
    OutOfTime,
    /// The agent is stopping, so the command was not started.
    Stopping,
    /// Exited with a failure status; `stderr` is its first line, made safe to log.
    Failed {
        status: String,
        stderr: String,
    },
    Io(String),
}

impl RunError {
    /// A sentence for a fact's `reason`: what was being run and why it gave nothing.
    pub fn reason(&self, what: &str) -> String {
        match self {
            Self::NotInstalled(paths) => format!("{what} is not installed ({paths} not found)"),
            Self::PermissionDenied(path) => format!("permission denied running {path}"),
            Self::TimedOut(limit) => format!(
                "{what} did not finish within {} seconds",
                limit.as_secs().max(1)
            ),
            Self::TooMuchOutput(limit) => {
                format!("{what} printed more than {limit} bytes; stopped it")
            }
            Self::OutOfTime => format!(
                "not run: the collection's time budget was used up before {what} could start"
            ),
            Self::Stopping => format!("not run: the agent is stopping, so {what} was not started"),
            Self::Failed { status, stderr } if stderr.is_empty() => {
                format!("{what} failed ({status})")
            }
            Self::Failed { status, stderr } => format!("{what} failed ({status}): {stderr}"),
            Self::Io(message) => format!("cannot run {what}: {message}"),
        }
    }
}

/// What the readers may do on the host. See the module documentation.
pub trait Host: Send + Sync {
    fn stat(&self, path: &Path) -> io::Result<Stat>;
    fn read(&self, path: &Path, max_bytes: u64) -> io::Result<Vec<u8>>;
    /// File names in `dir` (not paths), sorted. More than `max_entries` is an error.
    fn list(&self, dir: &Path, max_entries: usize) -> io::Result<Vec<String>>;
    /// Standard output of the command.
    fn run(&self, command: &Command) -> Result<Vec<u8>, RunError>;
}

/// Reads a file through `host`, refusing the paths that hold secrets ([`is_secret_path`]).
pub fn read_file(host: &dyn Host, path: &str, max_bytes: u64) -> io::Result<Vec<u8>> {
    if is_secret_path(path) {
        return Err(refused());
    }
    host.read(Path::new(path), max_bytes)
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "refused: this agent never reads secret files",
    )
}

/// Files whose contents are secret, or hold secrets: password hashes, group passwords, sudo rules,
/// SSH host and user private keys, and the old-password list. The agent reads none of them, and the
/// manifest's `file:` facts only `stat` them.
pub fn is_secret_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let base = name.trim_end_matches('-');
    matches!(base, "shadow" | "gshadow" | "opasswd" | "sudoers")
        || path.starts_with("/etc/sudoers.d")
        || (name.starts_with("ssh_host_") && !name.ends_with(".pub"))
        || name.starts_with("id_")
        || name.ends_with("_key")
        || name.ends_with(".key")
        || name.ends_with(".pem")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Op {
    Stat,
    Read,
    List,
}

type Blocked = Arc<Mutex<HashSet<(Op, PathBuf)>>>;

/// The real host. Cheap to clone; clones share the record of blocked calls.
#[derive(Clone, Default)]
pub struct RealHost {
    blocked: Blocked,
}

/// Removes a call from the blocked set when it returns, however it ends.
struct Release(Blocked, (Op, PathBuf));

impl Drop for Release {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.1);
    }
}

impl RealHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `f` on its own thread, giving up after [`IO_TIMEOUT`].
    fn bounded<T: Send + 'static>(
        &self,
        op: Op,
        path: &Path,
        f: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        let key = (op, path.to_owned());
        let fresh = self
            .blocked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone());
        if !fresh {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "still blocked by an earlier read of this path",
            ));
        }
        let release = Release(Arc::clone(&self.blocked), key);
        let (sender, receiver) = mpsc::channel();
        let target = path.to_owned();
        // If the thread cannot start, the closure (and `release` with it) is dropped, which frees the key.
        start_thread("fleet-agent-fact-io", move || {
            let _release = release;
            let _ = sender.send(f(&target));
        })?;
        match receiver.recv_timeout(IO_TIMEOUT) {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no answer within {} seconds", IO_TIMEOUT.as_secs()),
            )),
        }
    }
}

impl Host for RealHost {
    fn stat(&self, path: &Path) -> io::Result<Stat> {
        self.bounded(Op::Stat, path, |path| {
            let metadata = fs::metadata(path)?;
            Ok(Stat {
                mode: metadata.mode() & 0o7777,
                uid: metadata.uid(),
                gid: metadata.gid(),
            })
        })
    }

    fn read(&self, path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
        self.bounded(Op::Read, path, move |path| {
            // Reads follow symlinks, so the secret check also applies to where the path leads (Rust
            // practice review of #114): `pwquality.conf.d/x.conf -> /etc/shadow` is refused. It runs
            // inside the bounded call, so resolving a path on a dead mount cannot hang the agent, and
            // the resolved path is what is read.
            let resolved = fs::canonicalize(path)?;
            if resolved.to_str().is_none_or(is_secret_path) {
                return Err(refused());
            }
            fsx::read_regular(&resolved, max_bytes, Symlinks::Follow)
        })
    }

    fn list(&self, dir: &Path, max_entries: usize) -> io::Result<Vec<String>> {
        self.bounded(Op::List, dir, move |dir| {
            let mut names = Vec::new();
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if names.len() >= max_entries {
                    return Err(io::Error::other(format!(
                        "more than {max_entries} entries in {}",
                        dir.display()
                    )));
                }
                if let Ok(name) = entry.file_name().into_string() {
                    names.push(name);
                }
            }
            names.sort();
            Ok(names)
        })
    }

    fn run(&self, command: &Command) -> Result<Vec<u8>, RunError> {
        run(command)
    }
}

/// How much of a program's standard error is kept, only to quote its first line.
const MAX_STDERR: usize = 4096;
/// How long to wait for an output pipe to close after the program has exited.
const PIPE_GRACE: Duration = Duration::from_secs(2);

fn run(command: &Command) -> Result<Vec<u8>, RunError> {
    let program = command
        .programs
        .iter()
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file()))
        .ok_or_else(|| RunError::NotInstalled(command.programs.join(" or ")))?;
    let mut child = Process::new(program)
        .args(&command.args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("SYSTEMD_PAGER", "")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied => RunError::PermissionDenied((*program).to_owned()),
            io::ErrorKind::NotFound => RunError::NotInstalled((*program).to_owned()),
            _ => RunError::Io(crate::logging::sanitize(&e.to_string(), 200)),
        })?;
    let exceeded = Arc::new(AtomicBool::new(false));
    let pipes = child.stdout.take().zip(child.stderr.take());
    let drained = pipes.map(|(out, err)| {
        let stdout = drain(out, command.max_output, Some(Arc::clone(&exceeded)))?;
        let stderr = drain(err, MAX_STDERR, None)?;
        Ok::<_, io::Error>((stdout, stderr))
    });
    let (stdout, stderr) = match drained.transpose() {
        Ok(pipes) => pipes.unzip(),
        // A thread that cannot start (a task limit, memory pressure) fails this command, not the
        // agent (Rust practice review of #114).
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Io(format!(
                "cannot start a thread to read its output: {}",
                crate::logging::sanitize(&e.to_string(), 200)
            )));
        }
    };

    let deadline = Instant::now() + command.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::Io(crate::logging::sanitize(&e.to_string(), 200)));
            }
        }
        let failure = if exceeded.load(Ordering::Relaxed) {
            Some(RunError::TooMuchOutput(command.max_output))
        } else if Instant::now() >= deadline {
            Some(RunError::TimedOut(command.timeout))
        } else {
            None
        };
        if let Some(failure) = failure {
            let _ = child.kill();
            let _ = child.wait();
            return Err(failure);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let out = collect_pipe(stdout)?;
    let err = collect_pipe(stderr)?;
    if exceeded.load(Ordering::Relaxed) {
        return Err(RunError::TooMuchOutput(command.max_output));
    }
    if !status.success() {
        use std::os::unix::process::ExitStatusExt;
        let status_text = match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit status {code}"),
            (None, Some(signal)) => format!("terminated by signal {signal}"),
            _ => "failed".to_owned(),
        };
        let first_line = String::from_utf8_lossy(&err)
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(|l| crate::logging::sanitize(l, 200))
            .unwrap_or_default();
        return Err(RunError::Failed {
            status: status_text,
            stderr: first_line,
        });
    }
    Ok(out)
}

type Drained = mpsc::Receiver<Vec<u8>>;

/// Reads `pipe` on its own thread, keeping at most `limit` bytes; past that it stops reading (which
/// closes the pipe) and raises `exceeded`.
fn drain(
    mut pipe: impl Read + Send + 'static,
    limit: usize,
    exceeded: Option<Arc<AtomicBool>>,
) -> io::Result<Drained> {
    let (sender, receiver) = mpsc::channel();
    start_thread("fleet-agent-fact-pipe", move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if kept.len() + n > limit {
                        if let Some(flag) = &exceeded {
                            flag.store(true, Ordering::Relaxed);
                        }
                        break;
                    }
                    kept.extend_from_slice(&chunk[..n]);
                }
            }
        }
        let _ = sender.send(kept);
    })?;
    Ok(receiver)
}

/// Starts a named thread, returning the error rather than panicking as `thread::spawn` does.
fn start_thread(name: &str, f: impl FnOnce() + Send + 'static) -> io::Result<()> {
    #[cfg(test)]
    if tests::FAIL_THREAD_START.with(std::cell::Cell::get) {
        return Err(io::Error::other("simulated: no thread could be started"));
    }
    thread::Builder::new().name(name.into()).spawn(f).map(drop)
}

fn collect_pipe(pipe: Option<Drained>) -> Result<Vec<u8>, RunError> {
    match pipe {
        None => Ok(Vec::new()),
        Some(receiver) => receiver.recv_timeout(PIPE_GRACE).map_err(|_| {
            RunError::Io("an output pipe did not close after the program exited".into())
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn secret_paths_are_recognised() {
        for path in [
            "/etc/shadow",
            "/etc/shadow-",
            "/etc/gshadow",
            "/etc/gshadow-",
            "/etc/security/opasswd",
            "/etc/sudoers",
            "/etc/sudoers.d/90-cloud-init-users",
            "/etc/ssh/ssh_host_ed25519_key",
            "/root/.ssh/id_ed25519",
            "/etc/ssl/private/ssl-cert-snakeoil.key",
        ] {
            assert!(is_secret_path(path), "{path}");
        }
        for path in [
            "/etc/passwd",
            "/etc/group",
            "/etc/login.defs",
            "/etc/ssh/ssh_host_ed25519_key.pub",
            "/etc/security/pwquality.conf",
        ] {
            assert!(!is_secret_path(path), "{path}");
        }
    }

    #[test]
    fn stat_reports_mode_owner_and_group_and_follows_symlinks() {
        let dir = TempDir::new();
        let file = dir.write("f", "x");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o4750)).unwrap();
        let link = dir.path("link");
        symlink(&file, &link).unwrap();
        let host = RealHost::new();
        let direct = host.stat(&file).unwrap();
        assert_eq!(direct.mode, 0o4750);
        assert_eq!(host.stat(&link).unwrap(), direct);
        let meta = fs::metadata(&file).unwrap();
        assert_eq!((direct.uid, direct.gid), (meta.uid(), meta.gid()));
        let missing = host.stat(&dir.path("absent")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn reads_are_bounded_and_only_of_regular_files() {
        let dir = TempDir::new();
        let file = dir.write("f", "0123456789");
        let host = RealHost::new();
        assert_eq!(host.read(&file, 10).unwrap(), b"0123456789");
        assert!(host.read(&file, 9).is_err());
        assert!(host.read(dir.root(), 100).is_err());
    }

    #[test]
    fn a_symlink_to_a_secret_file_is_refused() {
        // Rust practice review of #114: only the requested path was checked, and reads follow links.
        let dir = TempDir::new();
        let secret = dir.write("shadow", "root:$y$not-a-real-hash:19000:0:99999:7:::\n");
        let link = dir.path("x.conf");
        symlink(&secret, &link).unwrap();
        let host = RealHost::new();
        let error = host.read(&link, 4096).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        // A link to an ordinary file is still read, and through `read_file` the same holds.
        let plain = dir.write("pwquality.conf", "minlen = 12\n");
        let ok_link = dir.path("y.conf");
        symlink(&plain, &ok_link).unwrap();
        assert_eq!(host.read(&ok_link, 4096).unwrap(), b"minlen = 12\n");
        let through = read_file(&host, link.to_str().unwrap(), 4096).unwrap_err();
        assert_eq!(through.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_fifo_is_refused_at_once_instead_of_waited_on() {
        let dir = TempDir::new();
        let fifo = dir.path("pipe");
        let made = Process::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|s| s.success()) {
            return; // no mkfifo here
        }
        let started = Instant::now();
        let host = RealHost::new();
        assert!(host.read(&fifo, 100).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn listing_is_sorted_and_bounded() {
        let dir = TempDir::new();
        for name in ["b.conf", "a.conf", "c.conf"] {
            dir.write(name, "");
        }
        let host = RealHost::new();
        assert_eq!(
            host.list(dir.root(), 10).unwrap(),
            ["a.conf", "b.conf", "c.conf"]
        );
        assert!(host.list(dir.root(), 2).is_err());
        assert!(host.list(&dir.path("absent"), 2).is_err());
    }

    fn sh(script: &str) -> Command {
        Command::new(&["/bin/sh", "/usr/bin/sh"], &["-c", script])
    }

    thread_local! {
        /// Makes [`start_thread`] fail on this test's thread, as a task limit or memory pressure would.
        pub(super) static FAIL_THREAD_START: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[test]
    fn a_thread_that_cannot_start_fails_the_command_not_the_agent() {
        // Rust practice review of #114: the output reader used `thread::spawn`, which panics when no
        // thread can be started, and the panic stopped the agent.
        FAIL_THREAD_START.with(|f| f.set(true));
        let started = Instant::now();
        let result = RealHost::new().run(&sh("exec sleep 30"));
        FAIL_THREAD_START.with(|f| f.set(false));
        match result {
            Err(RunError::Io(message)) => {
                assert!(message.contains("cannot start a thread"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        // The program was killed and reaped, not left to run out its 30 seconds.
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_command_returns_its_output() {
        let out = RealHost::new().run(&sh("printf 'a b\\n'")).unwrap();
        assert_eq!(out, b"a b\n");
    }

    #[test]
    fn a_command_does_not_see_the_agents_environment() {
        let out = RealHost::new()
            .run(&sh("printf '%s|%s' \"$HOME\" \"$LC_ALL\""))
            .unwrap();
        assert_eq!(out, b"|C");
    }

    #[test]
    fn a_failing_command_reports_its_status_and_first_stderr_line() {
        let error = RealHost::new()
            .run(&sh("echo 'boom: bad thing' >&2; echo more >&2; exit 3"))
            .unwrap_err();
        assert_eq!(
            error,
            RunError::Failed {
                status: "exit status 3".into(),
                stderr: "boom: bad thing".into()
            }
        );
        assert_eq!(
            error.reason("sshd -T"),
            "sshd -T failed (exit status 3): boom: bad thing"
        );
    }

    #[test]
    fn a_missing_program_is_not_installed() {
        let command = Command::new(&["/nonexistent/one", "/nonexistent/two"], &[]);
        let error = RealHost::new().run(&command).unwrap_err();
        assert_eq!(
            error,
            RunError::NotInstalled("/nonexistent/one or /nonexistent/two".into())
        );
        assert!(error.reason("sshd").contains("sshd is not installed"));
    }

    #[test]
    fn a_program_that_hangs_is_killed_at_the_time_limit() {
        let mut command = sh("exec sleep 30");
        command.timeout = Duration::from_millis(300);
        let started = Instant::now();
        let error = RealHost::new().run(&command).unwrap_err();
        assert_eq!(error, RunError::TimedOut(Duration::from_millis(300)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_program_that_prints_too_much_is_killed() {
        let mut command = sh("while true; do echo 0123456789abcdef; done");
        command.max_output = 10_000;
        let started = Instant::now();
        let error = RealHost::new().run(&command).unwrap_err();
        assert_eq!(error, RunError::TooMuchOutput(10_000));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_up_to_the_bound_is_kept() {
        let mut command = sh("printf 0123456789");
        command.max_output = 10;
        assert_eq!(RealHost::new().run(&command).unwrap(), b"0123456789");
    }
}
