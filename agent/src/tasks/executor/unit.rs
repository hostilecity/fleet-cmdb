//! `package_manager` programs in a transient systemd unit, outside the agent's sandbox (P3-A05,
//! threat model F-1, F-2, Q7).
//!
//! The agent's own unit keeps `ProtectSystem=strict` and one capability, so nothing that installs
//! packages can run inside it, and loosening it would loosen it for all agent code all the time.
//! Instead the agent asks systemd, over the local socket its unit already allows (`AF_UNIX`, the
//! update supervisor's path), to start the program as its own transient service:
//!
//! - named `fleet-agent-task-<task id>-<step>.service` ([`Generated::task_unit`]), which DEC-15's
//!   `fleet-agent*` rule protects from `restart_service`;
//! - with the fixed environment ([`super::spawn::ENVIRONMENT`]), working directory `/`, no standard
//!   input, and its output in the journal;
//! - with the fixed properties in [`PROPERTIES`]: the whole group killed when it stops, a hard
//!   `RuntimeMaxSec=` of the deadline plus [`STOP_GRACE`] that systemd enforces even if the agent is
//!   gone, and the agent's credential and state hidden from it (C11);
//! - `RemainAfterExit=yes`, so its result stays readable until the agent has collected it.
//!
//! The agent polls the unit's state. At the deadline it stops the unit (`SIGTERM`, then `SIGKILL`
//! after [`STOP_GRACE`]) and reports `timed_out`. An interruptible task is stopped on cancel or
//! shutdown; one that is not (`apply_package_updates`, DEC-16) is **left running when the agent
//! stops**: systemd keeps it alive outside the agent's cgroup, and the agent, when it starts again,
//! waits for it and reports what it did ([`Units::recover`], threat model L8) instead of cutting a
//! package upgrade short. Output is read back from the journal (`journalctl
//! _SYSTEMD_INVOCATION_ID=...`), through the same bounded [`Capture`].

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::output::Capture;
use super::spawn::{self, Arg, Exit, Generated, Limits, Program};
use super::{Control, Stop};

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const JOURNALCTL: &str = "/usr/bin/journalctl";

/// How long the unit has to exit after `SIGTERM` before systemd kills it. DEC-16 asks for a gentle
/// stop of the package manager, so this is longer than [`spawn::TERM_GRACE`].
pub const STOP_GRACE: Duration = Duration::from_secs(60);

/// How often the agent looks at the unit while it runs.
pub const POLL: Duration = Duration::from_secs(1);

/// The most transient units one task may start.
pub const MAX_STEPS: u32 = 4;

/// The longest any one helper call (`systemd-run`, `systemctl`, `journalctl`) may take.
const HELPER_TIMEOUT: Duration = Duration::from_secs(120);

/// The properties of every task unit, fixed (P3-A05's privilege table explains each). Kept to what
/// cannot break a package upgrade: dpkg and maintainer scripts write `/usr`, `/etc`, `/boot`,
/// `/var`, and `/root`, install setuid programs, probe devices, and rebuild initramfs images, so
/// `ProtectSystem=`, `ProtectHome=`, `RestrictSUIDSGID=`, `PrivateDevices=`, `NoNewPrivileges=`,
/// `ProtectKernelModules=`, and a capability bound are deliberately not set.
pub const PROPERTIES: &[&str] = &[
    "--property=Type=exec",
    "--property=RemainAfterExit=yes",
    "--property=KillMode=control-group",
    "--property=TimeoutStopSec=60",
    "--property=WorkingDirectory=/",
    "--property=StandardInput=null",
    "--property=StandardOutput=journal",
    "--property=StandardError=journal",
    // C11: the credential and the agent's state are not the task's business.
    "--property=InaccessiblePaths=-/etc/fleet-agent -/var/lib/fleet-agent",
    "--property=PrivateTmp=yes",
    "--property=ProtectKernelLogs=yes",
    "--property=LockPersonality=yes",
    "--property=RestrictRealtime=yes",
    "--property=SystemCallArchitectures=native",
    "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "--setenv=LANG=C",
    "--setenv=DEBIAN_FRONTEND=noninteractive",
];

/// A transient unit's state, as `systemctl show` reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// `loaded` or `not-found`.
    pub load: String,
    pub active: String,
    pub sub: String,
    /// `success`, `exit-code`, `signal`, `timeout`, ...
    pub result: String,
    /// `ExecMainCode`: 1 exited, 2 killed, 3 dumped core.
    pub main_code: Option<i32>,
    pub main_status: Option<i32>,
    pub invocation: String,
}

impl Status {
    /// Whether systemd has no such unit.
    pub fn missing(&self) -> bool {
        self.load == "not-found" || self.load.is_empty()
    }

    /// Whether the program is still running (or starting, or stopping).
    pub fn running(&self) -> bool {
        !self.missing()
            && match self.active.as_str() {
                "activating" | "deactivating" | "reloading" | "refreshing" => true,
                "active" => self.sub != "exited",
                _ => false,
            }
    }

    /// How the program ended.
    pub fn exit(&self) -> Exit {
        match self.main_code {
            Some(1) => Exit {
                code: self.main_status,
                signal: None,
            },
            Some(2 | 3) => Exit {
                code: None,
                signal: self.main_status,
            },
            _ => Exit {
                code: None,
                signal: None,
            },
        }
    }

    /// Whether systemd ended the program at its `RuntimeMaxSec=`. With `RemainAfterExit=yes` a
    /// program that had already exited can still reach that limit while it waits to be collected;
    /// that is not a timeout of the program.
    pub fn timed_out(&self) -> bool {
        self.result == "timeout" && self.main_code != Some(1)
    }

    /// Reads `systemctl show` output.
    pub fn parse(text: &str) -> Self {
        let mut status = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_owned();
            match key {
                "LoadState" => status.load = value,
                "ActiveState" => status.active = value,
                "SubState" => status.sub = value,
                "Result" => status.result = value,
                "ExecMainCode" => status.main_code = value.parse().ok(),
                "ExecMainStatus" => status.main_status = value.parse().ok(),
                "InvocationID" => status.invocation = value,
                _ => {}
            }
        }
        status
    }
}

/// The systemd calls, behind a trait so the tests can script systemd.
pub trait Units: Send + Sync {
    /// Starts `program` as the unit `name`, killed by systemd after `runtime_max_seconds`.
    fn start(
        &self,
        name: &Generated,
        program: &Program,
        runtime_max_seconds: u64,
    ) -> Result<(), String>;
    fn status(&self, name: &Generated) -> Result<Status, String>;
    /// Stops the unit and waits for it to stop.
    fn stop(&self, name: &Generated) -> Result<(), String>;
    /// Adds the output of one run of a unit to `capture`.
    fn journal(&self, invocation: &str, capture: &Arc<Mutex<Capture>>) -> Result<(), String>;
    /// Removes a finished unit (stop, then reset-failed), so its name is free.
    fn remove(&self, name: &Generated);
}

/// The real systemd, through its command-line tools, run like any task program.
pub struct Systemd;

/// A [`Control`] for helper calls: never cancels.
struct Helper<'a>(&'a crate::shutdown::Shutdown);

impl Control for Helper<'_> {
    fn shutdown(&self) -> &crate::shutdown::Shutdown {
        self.0
    }

    fn cancel_requested(&self) -> bool {
        false
    }
}

impl Systemd {
    fn call(path: &'static str, args: &[Arg<'_>]) -> Result<String, String> {
        // Helper calls are short and not interruptible: a shutdown waits for them (bounded).
        let shutdown = crate::shutdown::Shutdown::default();
        let capture = Arc::new(Mutex::new(Capture::default()));
        let limits = Limits {
            deadline: Instant::now() + HELPER_TIMEOUT,
            interruptible: false,
        };
        let ran = spawn::run(path, args, limits, &Helper(&shutdown), &capture);
        let (text, _) = spawn::lock(&capture).finish();
        match ran {
            Ok(exit) if exit.success() => Ok(text),
            Ok(_) | Err(_) => Err(crate::logging::sanitize(text.trim(), 500)),
        }
    }
}

impl Units for Systemd {
    fn start(
        &self,
        name: &Generated,
        program: &Program,
        runtime_max_seconds: u64,
    ) -> Result<(), String> {
        let runtime = Generated::runtime_max(runtime_max_seconds);
        let mut args = vec![
            Arg::Fixed("--unit"),
            Arg::Generated(name),
            Arg::Fixed("--description=Fleet agent task"),
            Arg::Fixed("--quiet"),
            Arg::Generated(&runtime),
        ];
        args.extend(PROPERTIES.iter().map(|p| Arg::Fixed(p)));
        args.push(Arg::Fixed("--"));
        args.push(Arg::Fixed(program.path));
        args.extend(program.argv());
        Self::call(SYSTEMD_RUN, &args).map(drop)
    }

    fn status(&self, name: &Generated) -> Result<Status, String> {
        Self::call(
            SYSTEMCTL,
            &[
                Arg::Fixed("show"),
                Arg::Fixed(
                    "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,InvocationID",
                ),
                Arg::Fixed("--"),
                Arg::Generated(name),
            ],
        )
        .map(|text| Status::parse(&text))
    }

    fn stop(&self, name: &Generated) -> Result<(), String> {
        Self::call(
            SYSTEMCTL,
            &[Arg::Fixed("stop"), Arg::Fixed("--"), Arg::Generated(name)],
        )
        .map(drop)
    }

    fn journal(&self, invocation: &str, capture: &Arc<Mutex<Capture>>) -> Result<(), String> {
        let Some(matching) = Generated::invocation_match(invocation) else {
            return Err("the unit has no invocation id".into());
        };
        let shutdown = crate::shutdown::Shutdown::default();
        let limits = Limits {
            deadline: Instant::now() + HELPER_TIMEOUT,
            interruptible: false,
        };
        let args = [
            Arg::Fixed("--quiet"),
            Arg::Fixed("--no-pager"),
            Arg::Fixed("--all"),
            Arg::Fixed("--output=cat"),
            Arg::Generated(&matching),
        ];
        match spawn::run(JOURNALCTL, &args, limits, &Helper(&shutdown), capture) {
            Ok(exit) if exit.success() => Ok(()),
            _ => Err("journalctl failed".into()),
        }
    }

    fn remove(&self, name: &Generated) {
        let _ = self.stop(name);
        let _ = Self::call(
            SYSTEMCTL,
            &[
                Arg::Fixed("reset-failed"),
                Arg::Fixed("--"),
                Arg::Generated(name),
            ],
        );
    }
}

/// Runs `program` as step `step` of task `task_id` in a transient unit, adding its output to
/// `capture`. `Err(Stop::Detached)`: the agent is stopping and the task, which cannot be
/// interrupted, was left running in its unit.
pub fn run(
    units: &dyn Units,
    task_id: &str,
    step: u32,
    program: &Program,
    limits: Limits,
    control: &dyn Control,
    capture: &Arc<Mutex<Capture>>,
) -> Result<Exit, Stop> {
    let Some(name) = Generated::task_unit(task_id, step).filter(|_| step <= MAX_STEPS) else {
        return Err(Stop::Failed("agent_error"));
    };
    let remaining = limits.deadline.saturating_duration_since(Instant::now());
    let runtime_max = remaining.as_secs() + 1 + STOP_GRACE.as_secs();
    if let Err(why) = units.start(&name, program, runtime_max) {
        tracing::error!(unit = name.as_str(), "cannot start a task unit: {why}");
        spawn::lock(capture).note(&format!("could not start {}: {why}", name.as_str()));
        units.remove(&name);
        return Err(Stop::Failed("agent_error"));
    }
    tracing::info!(
        unit = name.as_str(),
        program = program.path,
        "task unit started"
    );
    let mut failures = 0;
    loop {
        let status = match units.status(&name) {
            Ok(status) => {
                failures = 0;
                status
            }
            Err(why) => {
                failures += 1;
                tracing::warn!(
                    unit = name.as_str(),
                    "cannot read the task unit's state: {why}"
                );
                Status {
                    load: "loaded".into(),
                    active: "active".into(),
                    sub: "running".into(),
                    ..Status::default()
                }
            }
        };
        if !status.running() {
            return Ok(collect(units, &name, &status, capture));
        }
        let stop = if Instant::now() >= limits.deadline || failures >= 30 {
            Some(Stop::TimedOut)
        } else if limits.interruptible && control.cancel_requested() {
            Some(Stop::Cancelled)
        } else if control.shutdown().is_requested() {
            if !limits.interruptible {
                tracing::warn!(
                    unit = name.as_str(),
                    "the agent is stopping while a task that cannot be interrupted runs; it is left to finish in its unit, and its outcome is reported when the agent starts again"
                );
                return Err(Stop::Detached);
            }
            Some(Stop::Interrupted)
        } else {
            if !limits.interruptible {
                control.cancel_requested();
            }
            None
        };
        if let Some(stop) = stop {
            if failures >= 30 {
                tracing::error!(
                    unit = name.as_str(),
                    "the task unit's state cannot be read; stopping it"
                );
            }
            let _ = units.stop(&name);
            // A stopped unit may be gone at once; its output is still in the journal under the
            // invocation id it had while it ran.
            let mut last = units
                .status(&name)
                .ok()
                .filter(|s| !s.missing())
                .unwrap_or_default();
            if last.invocation.is_empty() {
                last.invocation = status.invocation.clone();
            }
            collect(units, &name, &last, capture);
            return Err(stop);
        }
        control.shutdown().wait(POLL);
    }
}

/// Reads the output of a finished unit, removes the unit, and says how its program ended.
pub fn collect(
    units: &dyn Units,
    name: &Generated,
    status: &Status,
    capture: &Arc<Mutex<Capture>>,
) -> Exit {
    if let Err(why) = units.journal(&status.invocation, capture) {
        spawn::lock(capture).note(&format!(
            "the output of {} could not be read: {why}",
            name.as_str()
        ));
    }
    units.remove(name);
    status.exit()
}

/// What a restarted agent finds of a task's units (threat model L8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// No unit of this task exists.
    None,
    /// A unit of this task is still running.
    Running,
    /// Every unit of this task has ended; their exits, in step order, with their output captured.
    Ended(Vec<Exit>, bool),
}

/// Looks for the units of `task_id`, and collects those that ended. Called on start-up for a task the
/// ledger shows as started but not finished.
pub fn recover(units: &dyn Units, task_id: &str, capture: &Arc<Mutex<Capture>>) -> Found {
    let mut statuses = Vec::new();
    for step in 1..=MAX_STEPS {
        let Some(name) = Generated::task_unit(task_id, step) else {
            return Found::None;
        };
        match units.status(&name) {
            Ok(status) if !status.missing() => statuses.push((name, status)),
            Ok(_) => {}
            // Unknown: wait rather than report a task that may still be running.
            Err(_) => return Found::Running,
        }
    }
    if statuses.is_empty() {
        return Found::None;
    }
    if statuses.iter().any(|(_, s)| s.running()) {
        return Found::Running;
    }
    let timed_out = statuses.iter().any(|(_, s)| s.timed_out());
    let exits = statuses
        .iter()
        .map(|(name, status)| collect(units, name, status, capture))
        .collect();
    Found::Ended(exits, timed_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemctl_show_is_read() {
        let status = Status::parse(
            "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainCode=1\nExecMainStatus=0\nInvocationID=0123456789abcdef0123456789abcdef\n",
        );
        assert!(!status.running());
        assert!(!status.missing());
        assert_eq!(
            status.exit(),
            Exit {
                code: Some(0),
                signal: None
            }
        );
        assert_eq!(status.invocation, "0123456789abcdef0123456789abcdef");

        let killed = Status::parse(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=timeout\nExecMainCode=2\nExecMainStatus=9\n",
        );
        assert!(!killed.running());
        assert!(killed.timed_out());
        assert_eq!(
            killed.exit(),
            Exit {
                code: None,
                signal: Some(9)
            }
        );

        for (active, sub, running) in [
            ("active", "running", true),
            ("activating", "start", true),
            ("deactivating", "stop-sigterm", true),
            ("active", "exited", false),
            ("inactive", "dead", false),
            ("failed", "failed", false),
        ] {
            let status = Status {
                load: "loaded".into(),
                active: active.into(),
                sub: sub.into(),
                ..Status::default()
            };
            assert_eq!(status.running(), running, "{active}/{sub}");
        }
        assert!(Status::parse("LoadState=not-found\nActiveState=inactive\n").missing());
        assert_eq!(
            Status::parse("garbage").exit(),
            Exit {
                code: None,
                signal: None
            }
        );
    }

    #[test]
    fn every_property_is_fixed_and_hides_the_credential() {
        assert!(
            PROPERTIES
                .iter()
                .all(|p| p.starts_with("--property=") || p.starts_with("--setenv="))
        );
        assert!(PROPERTIES.contains(&"--property=KillMode=control-group"));
        assert!(
            PROPERTIES
                .contains(&"--property=InaccessiblePaths=-/etc/fleet-agent -/var/lib/fleet-agent")
        );
        // The unit's environment is the same fixed set as a direct child's.
        let setenv: Vec<String> = PROPERTIES
            .iter()
            .filter_map(|p| p.strip_prefix("--setenv="))
            .map(str::to_owned)
            .collect();
        let fixed: Vec<String> = spawn::ENVIRONMENT
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        assert_eq!(setenv, fixed);
        assert_eq!(STOP_GRACE.as_secs().to_string(), "60");
        assert!(PROPERTIES.contains(&"--property=TimeoutStopSec=60"));
    }
}
