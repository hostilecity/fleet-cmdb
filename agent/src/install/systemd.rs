//! The systemd unit and the `systemctl` calls the installer makes (P1-A10).
//!
//! The unit is built into the binary (FR-1.6) and written by `install`. `systemctl` is run by absolute
//! path with a fixed, minimal environment, so neither `PATH` nor an `FLEET_ENROLLMENT_TOKEN` in the
//! installer's environment reaches it.

use std::path::Path;
use std::process::{Command, Stdio};

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

    fn is_enabled(&self) -> bool {
        self.systemctl(&["is-enabled", UNIT_NAME])
            .is_ok_and(|s| s == "enabled")
    }
}

/// The real `systemctl`.
pub struct Systemctl;

impl Systemd for Systemctl {
    fn unavailable(&self) -> Option<String> {
        // sd_booted(3): systemd is the running init only if this directory exists.
        if !Path::new("/run/systemd/system").is_dir() {
            return Some("systemd is not running on this machine (no /run/systemd/system)".into());
        }
        if !Path::new(SYSTEMCTL).exists() {
            return Some(format!("{SYSTEMCTL} is missing"));
        }
        None
    }

    fn systemctl(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new(SYSTEMCTL)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .env("SYSTEMD_PAGER", "")
            .env("SYSTEMD_COLORS", "0")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {SYSTEMCTL}: {e}"))?;
        let stdout = crate::logging::sanitize(String::from_utf8_lossy(&output.stdout).trim(), 2000);
        if output.status.success() {
            Ok(stdout)
        } else {
            let stderr =
                crate::logging::sanitize(String::from_utf8_lossy(&output.stderr).trim(), 2000);
            Err(if stdout.is_empty() { stderr } else { stdout })
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
}
