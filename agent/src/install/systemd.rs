//! The systemd unit and the `systemctl` calls the installer makes (P1-A10).
//!
//! The unit is built into the binary (FR-1.6) and written by `install`. `systemctl` is run by absolute
//! path with a fixed, minimal environment, so neither `PATH` nor an `FLEET_ENROLLMENT_TOKEN` in the
//! installer's environment reaches it.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const UNIT_NAME: &str = "fleet-agent.service";

/// The unit file, written to `/etc/systemd/system/fleet-agent.service`.
pub const UNIT: &str = include_str!("fleet-agent.service");

/// The first line of every unit file the installer wrote. A unit without it is not the installer's, so
/// it is neither replaced nor removed.
pub const UNIT_MARKER: &str = "# Written by `fleet-agent install`";

const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// `systemctl`, behind a trait so tests can record the calls and script the answers.
pub trait Systemd {
    /// Why systemd cannot be used on this machine, if it cannot.
    fn unavailable(&self) -> Option<String>;

    /// Runs `systemctl ARGS`, returning its trimmed stdout, or what went wrong.
    fn systemctl(&self, args: &[&str]) -> Result<String, String>;

    fn daemon_reload(&self) -> Result<(), String> {
        self.systemctl(&["daemon-reload"]).map(drop)
    }

    /// `active`, `activating`, `inactive`, `failed`, ... (`systemctl is-active` exits nonzero for
    /// anything but active, so only its output is used).
    fn state(&self) -> String {
        match self.systemctl(&["is-active", UNIT_NAME]) {
            Ok(state) => state,
            Err(output) => output.lines().next().unwrap_or("unknown").trim().to_owned(),
        }
    }

    /// The service's main process id, while it runs (`systemctl show --property=MainPID`).
    fn main_pid(&self) -> Option<u32> {
        self.systemctl(&["show", "--property=MainPID", "--value", UNIT_NAME])
            .ok()
            .and_then(|pid| pid.trim().parse().ok())
            .filter(|pid| *pid > 0)
    }

    fn is_enabled(&self) -> bool {
        self.systemctl(&["is-enabled", UNIT_NAME])
            .is_ok_and(|s| s == "enabled")
    }
}

/// The real `systemctl`, run with a time limit: a wedged systemd or D-Bus must not hang the installer,
/// which may run unattended from cloud-init (review of #67).
pub struct Systemctl {
    path: PathBuf,
    timeout: Duration,
}

impl Default for Systemctl {
    fn default() -> Self {
        Self {
            path: PathBuf::from(SYSTEMCTL),
            timeout: SYSTEMCTL_TIMEOUT,
        }
    }
}

/// Longest any one `systemctl` call may take. `daemon-reload` on a busy machine is the slowest; a
/// minute is generous for all of them.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(60);

/// Most output kept from one call (it is only shown in error messages).
const MAX_OUTPUT: u64 = 64 * 1024;

impl Systemd for Systemctl {
    fn unavailable(&self) -> Option<String> {
        // sd_booted(3): systemd is the running init only if this directory exists.
        if !Path::new("/run/systemd/system").is_dir() {
            return Some("systemd is not running on this machine (no /run/systemd/system)".into());
        }
        if !self.path.exists() {
            return Some(format!("{} is missing", self.path.display()));
        }
        None
    }

    fn systemctl(&self, args: &[&str]) -> Result<String, String> {
        let shown = format!("systemctl {}", args.join(" "));
        let mut child = Command::new(&self.path)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .env("SYSTEMD_PAGER", "")
            .env("SYSTEMD_COLORS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.path.display()))?;
        // Read both pipes while waiting, so a chatty child cannot block on a full pipe.
        let reader = |pipe: Option<Box<dyn Read + Send>>| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                if let Some(pipe) = pipe {
                    let _ = pipe.take(MAX_OUTPUT).read_to_end(&mut bytes);
                }
                bytes
            })
        };
        let stdout = reader(
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        );
        let stderr = reader(
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        );
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{shown} did not finish within {} seconds and was stopped; systemd may be busy or stuck (check `systemctl status`)",
                        self.timeout.as_secs()
                    ));
                }
                Err(e) => return Err(format!("cannot wait for {shown}: {e}")),
            }
        };
        let text = |handle: thread::JoinHandle<Vec<u8>>| {
            let bytes = handle.join().unwrap_or_default();
            crate::logging::sanitize(String::from_utf8_lossy(&bytes).trim(), 2000)
        };
        let (stdout, stderr) = (text(stdout), text(stderr));
        if status.success() {
            Ok(stdout)
        } else if stdout.is_empty() {
            Err(stderr)
        } else {
            Err(stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_starts_the_current_version_and_is_marked_as_ours() {
        assert!(UNIT.starts_with(UNIT_MARKER));
        assert!(UNIT.contains("ExecStart=/usr/lib/fleet-agent/current/fleet-agent run\n"));
        assert!(UNIT.contains("Restart=on-failure\n"));
        assert!(UNIT.contains("RestartPreventExitStatus=78\n"));
        assert!(UNIT.contains("StateDirectory=fleet-agent\n"));
        assert!(UNIT.contains("WantedBy=multi-user.target\n"));
        // The agent runs as root (DEC-03): no User= line.
        assert!(!UNIT.contains("User="));
    }

    fn fake(script: &str, timeout: Duration) -> (crate::test_support::TempDir, Systemctl) {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_support::TempDir::new();
        let path = dir.write("systemctl", &format!("#!/bin/sh\n{script}\n"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, Systemctl { path, timeout })
    }

    #[test]
    fn a_hung_systemctl_is_stopped_at_the_time_limit() {
        // Review of #67: a wedged systemd must not hang the installer.
        let (_dir, systemctl) = fake("sleep 30", Duration::from_millis(300));
        let started = Instant::now();
        let error = systemctl.systemctl(&["daemon-reload"]).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(
            error.contains("systemctl daemon-reload did not finish within"),
            "{error}"
        );
    }

    #[test]
    fn output_and_failures_are_reported() {
        let (_dir, systemctl) = fake(
            "if [ \"$1\" = is-active ]; then echo inactive; exit 3; fi\necho \"ran $*\"",
            Duration::from_secs(10),
        );
        assert_eq!(
            systemctl.systemctl(&["enable", UNIT_NAME]).unwrap(),
            "ran enable fleet-agent.service"
        );
        assert_eq!(systemctl.state(), "inactive");
        // A large output cannot block the child on a full pipe.
        let (_dir, systemctl) = fake(
            "head -c 1000000 /dev/zero | tr '\\0' x; exit 1",
            Duration::from_secs(10),
        );
        let error = systemctl.systemctl(&["status"]).unwrap_err();
        assert!(error.len() <= 2000 + 3, "{}", error.len());
    }
}
