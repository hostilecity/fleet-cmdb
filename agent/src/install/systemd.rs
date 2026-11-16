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

/// The unit `OnFailure=` of the service starts, which rolls an unconfirmed update back when the new
/// version keeps failing (P1-AGENT-UPDATE, ADR 0018). Written by `install` next to the service unit.
pub const ROLLBACK_UNIT_NAME: &str = "fleet-agent-rollback.service";
pub const ROLLBACK_UNIT: &str = include_str!("fleet-agent-rollback.service");

/// The unit `OnFailure=` starts after the rollback unit: recovery mode, for a version that keeps failing
/// with nothing to roll back to (#180, ADR 0030). Written by `install` next to the service unit.
pub const RECOVERY_UNIT_NAME: &str = "fleet-agent-recovery.service";
pub const RECOVERY_UNIT: &str = include_str!("fleet-agent-recovery.service");

/// The first line of every unit file the installer wrote. A unit without it is not the installer's, so
/// it is neither replaced nor removed.
pub const UNIT_MARKER: &str = "# Written by `fleet-agent install`";

/// Where `install` writes the units.
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// Most of a unit file [`recovery_covered`] reads (the units are about 3 KiB).
const MAX_UNIT_BYTES: u64 = 64 * 1024;

/// What the heartbeat reports about the installed units (#232): whether recovery mode is set up (ADR
/// 0030). Read from the files in `unit_dir` on every heartbeat, so a refresh after an update (which does
/// not restart the service) shows at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Units {
    pub recovery: bool,
}

/// Whether recovery mode is set up in `unit_dir`: the recovery unit is there and carries the installer's
/// marker, and the service names it in `OnFailure=` (#232). Both files are readable inside the sandbox
/// (`ProtectSystem=strict` keeps `/etc` readable). A missing file is `Ok(false)`; a file that cannot be
/// read is an error, which the heartbeat reports as `false` (it cannot tell that recovery mode is set
/// up). Drop-ins are not read: the installer writes none, and the dashboard's answer is only a guide.
pub fn recovery_covered(unit_dir: &Path) -> Result<bool, String> {
    let read = |name: &str| -> Result<Option<String>, String> {
        let path = unit_dir.join(name);
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let mut bytes = Vec::new();
        file.take(MAX_UNIT_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    };
    let Some(recovery) = read(RECOVERY_UNIT_NAME)? else {
        return Ok(false);
    };
    if !recovery.starts_with(UNIT_MARKER) {
        return Ok(false);
    }
    let Some(service) = read(UNIT_NAME)? else {
        return Ok(false);
    };
    Ok(on_failure(&service).contains(&RECOVERY_UNIT_NAME))
}

/// The units `OnFailure=` names in the `[Unit]` section of `unit`, as systemd reads them: each line adds
/// to the list, and an empty value clears it.
fn on_failure(unit: &str) -> Vec<&str> {
    let mut section = "";
    let mut units = Vec::new();
    for line in unit.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
            continue;
        }
        if section != "[Unit]" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "OnFailure" {
            continue;
        }
        if value.trim().is_empty() {
            units.clear();
        }
        units.extend(value.split_whitespace());
    }
    units
}

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";

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

impl Systemctl {
    /// The same runner (absolute path, fixed environment, time limit) for `systemd-run`, which the
    /// updater uses to start its supervisor outside the agent's sandbox.
    pub fn systemd_run() -> Self {
        Self {
            path: PathBuf::from(SYSTEMD_RUN),
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

    #[test]
    fn the_contrib_copy_is_the_unit_the_installer_writes() {
        // P1-PACKAGING keeps a copy in agent/contrib/ for review. This file is the source; after
        // changing it, run `cp src/install/fleet-agent.service contrib/` in agent/.
        assert!(
            UNIT == include_str!("../../contrib/fleet-agent.service"),
            "agent/contrib/fleet-agent.service differs from agent/src/install/fleet-agent.service"
        );
    }

    #[test]
    fn a_crash_loop_ends_in_the_rollback_unit() {
        // P1-AGENT-UPDATE: four starts in five minutes is a crash loop; systemd then gives up and starts
        // the unit that rolls back an unconfirmed update. RestartSec=10s alone would never reach
        // systemd's default limit (five starts in ten seconds).
        assert_eq!(values("StartLimitIntervalSec"), ["300"]);
        assert_eq!(values("StartLimitBurst"), ["4"]);
        // ADR 0030: the rollback unit first, then recovery mode, which waits for it (After=).
        assert_eq!(
            values("OnFailure"),
            [format!("{ROLLBACK_UNIT_NAME} {RECOVERY_UNIT_NAME}")]
        );
        assert_eq!(values("Restart"), ["on-failure"]);
        // Review of #222: OnFailure= only once the restarts have ended, not after every failed start.
        assert_eq!(values("RestartMode"), ["direct"]);
    }

    /// The values of `key=` in the recovery unit, in order.
    fn recovery_values(key: &str) -> Vec<&'static str> {
        RECOVERY_UNIT
            .lines()
            .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .collect()
    }

    #[test]
    fn the_recovery_unit_runs_the_current_version_after_the_rollback_unit_and_never_gives_up() {
        // #180, ADR 0030.
        assert!(RECOVERY_UNIT.starts_with(UNIT_MARKER));
        assert_eq!(
            recovery_values("ExecStart"),
            ["/usr/lib/fleet-agent/current/fleet-agent run --recovery"]
        );
        // The rollback unit has its turn first. No Conflicts=: on a systemd that starts this unit after
        // every failed start, a conflict would cancel the service's own restart. The agent itself checks
        // the service instead (`recovery::look`, used by `main::recover` and its watcher).
        assert_eq!(
            recovery_values("After"),
            [format!("network-online.target {ROLLBACK_UNIT_NAME}")]
        );
        assert!(recovery_values("Conflicts").is_empty());
        // Never stopped for good: no start limit, restarts after a long delay, whatever the exit status.
        assert_eq!(recovery_values("StartLimitIntervalSec"), ["0"]);
        assert_eq!(recovery_values("Restart"), ["on-failure"]);
        assert_eq!(recovery_values("RestartSec"), ["5min"]);
        assert_eq!(recovery_values("RestartMaxDelaySec"), ["1h"]);
        assert!(recovery_values("RestartPreventExitStatus").is_empty());
        // Nothing starts it at boot: only OnFailure= (or a person on the VM).
        assert!(!RECOVERY_UNIT.contains("[Install]"));
        assert!(
            RECOVERY_UNIT == include_str!("../../contrib/fleet-agent-recovery.service"),
            "agent/contrib/fleet-agent-recovery.service differs from the installer's"
        );
    }

    #[test]
    fn the_recovery_sandbox_is_the_services_or_tighter() {
        // ADR 0030: recovery mode gains no privilege. Every sandbox option of the service is set the same
        // way, except the three it tightens.
        let tightened = [
            "CapabilityBoundingSet",
            "ProtectHome",
            "RestrictAddressFamilies",
        ];
        let sandbox = UNIT
            .split("[Service]")
            .nth(1)
            .unwrap()
            .split("[Install]")
            .next()
            .unwrap();
        let mut checked = 0;
        for line in sandbox.lines() {
            let Some((key, _)) = line.split_once('=') else {
                continue;
            };
            if line.starts_with('#')
                || tightened.contains(&key)
                || [
                    "Type",
                    "ExecStart",
                    "Restart",
                    "RestartSec",
                    "RestartPreventExitStatus",
                    "RestartMode",
                ]
                .contains(&key)
            {
                continue;
            }
            assert!(
                RECOVERY_UNIT.lines().any(|l| l == line),
                "the recovery unit lacks the service's `{line}`"
            );
            checked += 1;
        }
        assert!(checked >= 20, "only {checked} options compared");
        assert_eq!(values("CapabilityBoundingSet"), ["CAP_DAC_READ_SEARCH"]);
        assert_eq!(recovery_values("CapabilityBoundingSet"), [""]);
        assert_eq!(recovery_values("ProtectHome"), ["yes"]);
        let service: Vec<&str> = values("RestrictAddressFamilies")[0].split(' ').collect();
        for family in recovery_values("RestrictAddressFamilies")[0].split(' ') {
            assert!(
                service.contains(&family),
                "{family} is not allowed to the service"
            );
        }
        assert_eq!(
            recovery_values("RestrictAddressFamilies"),
            ["AF_UNIX AF_INET AF_INET6"]
        );
        for widening in [
            "AmbientCapabilities",
            "ReadWritePaths",
            "User",
            "PrivateUsers",
        ] {
            assert!(recovery_values(widening).is_empty(), "{widening}");
        }
    }

    #[test]
    fn the_rollback_unit_runs_the_previous_version_and_is_marked_as_ours() {
        assert!(ROLLBACK_UNIT.starts_with(UNIT_MARKER));
        assert!(ROLLBACK_UNIT.contains(
            "ExecStart=/usr/lib/fleet-agent/previous/fleet-agent update-rollback --reason crash-loop\n"
        ));
        assert!(ROLLBACK_UNIT.contains("Type=oneshot\n"));
        // It must be able to change /usr/lib/fleet-agent and the state directory.
        assert!(!ROLLBACK_UNIT.contains("ProtectSystem"));
        assert!(
            ROLLBACK_UNIT == include_str!("../../contrib/fleet-agent-rollback.service"),
            "agent/contrib/fleet-agent-rollback.service differs from the installer's"
        );
    }

    /// The values of `key=` in the unit, in order.
    fn values(key: &str) -> Vec<&'static str> {
        UNIT.lines()
            .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .collect()
    }

    #[test]
    fn the_sandbox_keeps_what_the_agent_needs() {
        // P1-PACKAGING: every hardening option must leave the agent able to read /etc/fleet-agent,
        // /proc, /sys, and the mount table, statvfs every mount, reach the network, and write its
        // state directory. These are the options that would silently break one of those.
        assert_eq!(values("StateDirectory"), ["fleet-agent"]);
        assert_eq!(
            Path::new("/var/lib").join(values("StateDirectory")[0]),
            Path::new(crate::config::DEFAULT_STATE_DIR),
            "ProtectSystem=strict leaves only the StateDirectory= writable"
        );
        // Hiding /home (ProtectHome=yes or tmpfs) would replace a /home disk by an empty mount.
        assert_eq!(values("ProtectHome"), ["read-only"]);
        // /proc/cpuinfo, /proc/meminfo, /proc/net/route are not per-process files.
        assert!(values("ProcSubset").is_empty());
        // A private UTS namespace would freeze the hostname the agent reports.
        assert!(values("ProtectHostname").is_empty());
        // Network to the server; netlink for getifaddrs(3).
        assert!(values("PrivateNetwork").is_empty());
        assert!(values("IPAddressDeny").is_empty());
        // AF_UNIX is for `systemd-run`, which starts the update supervisor (P1-AGENT-UPDATE).
        assert_eq!(
            values("RestrictAddressFamilies"),
            ["AF_UNIX AF_INET AF_INET6 AF_NETLINK"]
        );
        // Root without a user namespace: PrivateUsers= would hide root-owned files' ownership.
        assert!(values("PrivateUsers").is_empty());
        assert!(values("DynamicUser").is_empty());
        // Blocked system calls fail with an error the collectors report, rather than killing the
        // agent, and statfs/statvfs, getrandom, and sockets are in @system-service.
        assert_eq!(values("SystemCallErrorNumber"), ["EPERM"]);
        assert_eq!(
            values("SystemCallFilter"),
            ["@system-service", "~@privileged @resources"]
        );
        // The one capability: searching directories root does not own, for statvfs and reads.
        assert_eq!(values("CapabilityBoundingSet"), ["CAP_DAC_READ_SEARCH"]);
        assert!(values("AmbientCapabilities").is_empty());
    }

    #[test]
    fn recovery_mode_is_covered_only_by_the_installers_unit_named_in_on_failure() {
        // #232: what heartbeats report as `units.recovery`.
        let dir = crate::test_support::TempDir::new();
        let units = dir.path("units");
        std::fs::create_dir_all(&units).unwrap();
        let write = |name: &str, text: &str| std::fs::write(units.join(name), text).unwrap();
        // Nothing installed, then only the service.
        assert_eq!(recovery_covered(&units), Ok(false));
        assert_eq!(recovery_covered(&dir.path("missing")), Ok(false));
        write(UNIT_NAME, UNIT);
        assert_eq!(recovery_covered(&units), Ok(false));
        // This release's units.
        write(RECOVERY_UNIT_NAME, RECOVERY_UNIT);
        assert_eq!(recovery_covered(&units), Ok(true));
        // A service from before recovery mode: OnFailure= names only the rollback unit.
        let old = UNIT.replace(
            &format!("OnFailure={ROLLBACK_UNIT_NAME} {RECOVERY_UNIT_NAME}"),
            &format!("OnFailure={ROLLBACK_UNIT_NAME}"),
        );
        assert_ne!(old, UNIT);
        write(UNIT_NAME, &old);
        assert_eq!(recovery_covered(&units), Ok(false));
        // Added on a line of its own, as systemd adds them; an empty value clears what came before.
        write(
            UNIT_NAME,
            &format!("{old}\n[Unit]\nOnFailure={RECOVERY_UNIT_NAME}\n"),
        );
        assert_eq!(recovery_covered(&units), Ok(true));
        write(UNIT_NAME, &format!("{UNIT}\n[Unit]\nOnFailure=\n"));
        assert_eq!(recovery_covered(&units), Ok(false));
        // Named outside [Unit], or in a comment, does not count.
        write(
            UNIT_NAME,
            &format!("{old}\n[Service]\nOnFailure={RECOVERY_UNIT_NAME}\n"),
        );
        assert_eq!(recovery_covered(&units), Ok(false));
        write(
            UNIT_NAME,
            &format!("{old}\n[Unit]\n# OnFailure={RECOVERY_UNIT_NAME}\n"),
        );
        assert_eq!(recovery_covered(&units), Ok(false));
        // A recovery unit someone wrote by hand is not the installer's.
        write(UNIT_NAME, UNIT);
        write(
            RECOVERY_UNIT_NAME,
            &RECOVERY_UNIT.replacen(UNIT_MARKER, "# my copy", 1),
        );
        assert_eq!(recovery_covered(&units), Ok(false));
        // A file that cannot be read is an error, not a guess.
        std::fs::remove_file(units.join(RECOVERY_UNIT_NAME)).unwrap();
        std::fs::create_dir(units.join(RECOVERY_UNIT_NAME)).unwrap();
        let error = recovery_covered(&units).unwrap_err();
        assert!(error.contains(RECOVERY_UNIT_NAME), "{error}");
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
