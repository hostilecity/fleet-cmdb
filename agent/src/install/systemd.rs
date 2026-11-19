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
/// 0030). Checked on every heartbeat, so a refresh after an update (which does not restart the service)
/// shows at once. `recovery` is `None` (sent as `null`) when the agent could not check: a unit file it cannot
/// read, or a `systemctl` that does not answer (re-review of #235), which the dashboard shows apart from
/// "not set up".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Units {
    pub recovery: Option<bool>,
}

/// `systemctl show --property=KEY... UNIT`, as a map with every key. The runner joins the output's lines
/// with spaces ([`crate::logging::sanitize`]), so it is split at the known keys: a token `KEY=value` starts
/// a key, and any other token belongs to the value before it (`OnFailure=` lists units separated by spaces;
/// no unit name or path systemd prints here holds `=`). One unit per call, so blocks never run together.
fn show(
    systemd: &dyn Systemd,
    unit: &str,
    keys: &[&str],
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut args = vec!["show".to_owned()];
    args.extend(keys.iter().map(|k| format!("--property={k}")));
    args.push(unit.to_owned());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = systemd
        .systemctl(&args)
        .map_err(|e| format!("systemctl show {unit} failed: {e}"))?;
    let mut found: std::collections::HashMap<String, Vec<&str>> = std::collections::HashMap::new();
    let mut current: Option<&str> = None;
    for token in output.split_whitespace() {
        match token.split_once('=') {
            Some((key, value)) if keys.contains(&key) => {
                current = Some(key);
                let values = found.entry(key.to_owned()).or_default();
                values.clear();
                values.extend(Some(value).filter(|v| !v.is_empty()));
            }
            _ => {
                if let Some(key) = current {
                    found.entry(key.to_owned()).or_default().push(token);
                }
            }
        }
    }
    keys.iter()
        .map(|key| {
            found
                .get(*key)
                .map(|v| ((*key).to_owned(), v.join(" ")))
                .ok_or_else(|| format!("systemctl show {unit} did not say {key}"))
        })
        .collect()
}

/// Whether recovery mode is set up, as systemd has loaded it (#232, review of #235): the service's
/// `OnFailure=` (drop-ins included) names the recovery unit, the recovery unit is loaded from `unit_dir`
/// and that file carries the installer's marker, and neither unit waits for a `daemon-reload` (otherwise
/// systemd still runs the settings from before the files changed). Asked with two `systemctl show` calls,
/// one per unit (`show`), which work inside the sandbox (`AF_UNIX`; the recovery unit has no capabilities
/// and needs none for them); each is bounded by the runner's time limit (10 s on the heartbeat path). A
/// recovery unit that is missing, or not the installer's, is `Ok(false)`; a file that cannot be read, or a
/// `systemctl show` that fails, times out, or leaves out a property, is an error, which the heartbeat
/// reports as `null` (could not check; `Heartbeat::units`).
pub fn recovery_covered(unit_dir: &Path, systemd: &dyn Systemd) -> Result<bool, String> {
    let fragment = unit_dir.join(RECOVERY_UNIT_NAME);
    match read_unit(&fragment)? {
        Some(text) if text.starts_with(UNIT_MARKER) => {}
        _ => return Ok(false),
    }
    let service = show(systemd, UNIT_NAME, &["OnFailure", "NeedDaemonReload"])?;
    let recovery = show(
        systemd,
        RECOVERY_UNIT_NAME,
        &["LoadState", "FragmentPath", "NeedDaemonReload"],
    )?;
    let named = service["OnFailure"]
        .split_whitespace()
        .any(|u| u == RECOVERY_UNIT_NAME);
    let loaded =
        recovery["LoadState"] == "loaded" && Path::new(&recovery["FragmentPath"]) == fragment;
    let reloaded = service["NeedDaemonReload"] == "no" && recovery["NeedDaemonReload"] == "no";
    Ok(named && loaded && reloaded)
}

/// The text of a unit file, at most [`MAX_UNIT_BYTES`], or `None` when there is none. Only a regular file is
/// read, and it is opened without blocking, so a FIFO put in its place cannot hang the heartbeat (review of
/// #235); anything else there is an error.
pub fn read_unit(path: &Path) -> Result<Option<String>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let regular = file.metadata().is_ok_and(|m| m.is_file());
    if !regular {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_UNIT_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// Whether systemd has to reload to see the unit files as they are now: `NeedDaemonReload=yes` for any of the
/// three units, or `systemctl` cannot say (then reloading is the safe choice). A run that wrote the files and
/// then failed, or was killed, before its reload leaves exactly this (review of #235).
pub fn needs_reload(systemd: &dyn Systemd) -> bool {
    match systemd.systemctl(&[
        "show",
        "--property=NeedDaemonReload",
        "--value",
        UNIT_NAME,
        ROLLBACK_UNIT_NAME,
        RECOVERY_UNIT_NAME,
    ]) {
        // One value per unit; the runner joins the lines with spaces.
        Ok(output) => output.split_whitespace().any(|v| v != "no"),
        Err(_) => true,
    }
}

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMD_ANALYZE: &str = "/usr/bin/systemd-analyze";

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

    /// `systemd-analyze verify` on unit files (review of #235): `Ok` with what it printed (warnings, which
    /// systemd only ignores), `Err` when systemd would refuse to load one of them. The fakes of the tests
    /// accept everything unless a test says otherwise.
    fn verify(&self, files: &[PathBuf]) -> Result<String, String> {
        let _ = files;
        Ok(String::new())
    }

    /// Why `systemd-analyze` cannot be run, if it cannot (re-review of #235): then the units cannot be
    /// checked, which is not the release's fault and gets its own message.
    fn analyze_unavailable(&self) -> Option<String> {
        None
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
    /// `systemctl` with a shorter limit, for a call on the heartbeat path ([`recovery_covered`]).
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            path: PathBuf::from(SYSTEMCTL),
            timeout,
        }
    }

    /// The same runner (absolute path, fixed environment, time limit) for `systemd-run`, which the
    /// updater uses to start its supervisor outside the agent's sandbox.
    pub fn systemd_run() -> Self {
        Self {
            path: PathBuf::from(SYSTEMD_RUN),
            timeout: SYSTEMCTL_TIMEOUT,
        }
    }
}

/// One of a child's output pipes, read without blocking: what it holds now is read, at most [`MAX_OUTPUT`]
/// bytes kept and the rest read and dropped, so the child never blocks on a full pipe.
struct Pipe {
    file: std::fs::File,
    bytes: Vec<u8>,
    open: bool,
}

impl Pipe {
    fn new(fd: std::os::fd::OwnedFd) -> Self {
        use std::os::fd::AsRawFd;
        // SAFETY: fcntl on a descriptor this Pipe owns; it changes only its file status flags.
        let open = unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            flags >= 0 && libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
        };
        Self {
            file: std::fs::File::from(fd),
            bytes: Vec::new(),
            open,
        }
    }

    /// Reads what the pipe holds now, until it would block or reaches its end.
    fn drain(&mut self) {
        let mut buf = [0u8; 8192];
        while self.open {
            match self.file.read(&mut buf) {
                Ok(0) => self.open = false,
                Ok(n) => {
                    let room = (MAX_OUTPUT as usize).saturating_sub(self.bytes.len());
                    self.bytes.extend_from_slice(&buf[..n.min(room)]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break, // WouldBlock: nothing more for now
            }
        }
    }
}

/// Longest any one `systemctl` call may take. `daemon-reload` on a busy machine is the slowest; a
/// minute is generous for all of them.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(60);

/// Most output kept from one call (it is only shown in error messages).
const MAX_OUTPUT: u64 = 64 * 1024;

impl Systemd for Systemctl {
    fn analyze_unavailable(&self) -> Option<String> {
        (!Path::new(SYSTEMD_ANALYZE).exists()).then(|| format!("{SYSTEMD_ANALYZE} is missing"))
    }

    fn verify(&self, files: &[PathBuf]) -> Result<String, String> {
        let analyze = Self {
            path: PathBuf::from(SYSTEMD_ANALYZE),
            timeout: self.timeout,
        };
        if !analyze.path.exists() {
            return Err(format!("{} is missing", analyze.path.display()));
        }
        let paths: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
        let mut args = vec!["verify", "--man=no"];
        args.extend(paths.iter().map(String::as_str));
        analyze.systemctl(&args)
    }

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
        // Read both pipes while waiting, so a chatty child cannot block on a full pipe. They are read without
        // blocking from this thread, not by reader threads: the heartbeat runs this twice a minute (#232), and
        // the soak test counts the agent's threads (re-review of #235).
        let mut pipes = [
            child.stdout.take().map(|p| Pipe::new(p.into())),
            child.stderr.take().map(|p| Pipe::new(p.into())),
        ];
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            for pipe in pipes.iter_mut().flatten() {
                pipe.drain();
            }
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
        // What it wrote just before it exited. A descendant that kept a pipe open cannot hold this up: the
        // pipes do not block.
        for pipe in pipes.iter_mut().flatten() {
            pipe.drain();
        }
        let text = |pipe: Option<Pipe>| {
            let bytes = pipe.map(|p| p.bytes).unwrap_or_default();
            crate::logging::sanitize(String::from_utf8_lossy(&bytes).trim(), 2000)
        };
        let [stdout, stderr] = pipes;
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

/// A stand-in for what systemd has loaded, for tests (review of #235): the unit files in `dir` as they were
/// at the last `daemon-reload`, and `systemctl show` answered from that, as systemd does.
#[cfg(test)]
#[derive(Clone)]
pub struct LoadedUnits {
    pub dir: PathBuf,
    loaded: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
}

#[cfg(test)]
impl LoadedUnits {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            loaded: std::sync::Arc::default(),
        }
    }

    /// `daemon-reload`: what is on disk now is what systemd runs.
    pub fn reload(&self) {
        let mut loaded = self.loaded.lock().unwrap();
        loaded.clear();
        for name in [UNIT_NAME, ROLLBACK_UNIT_NAME, RECOVERY_UNIT_NAME] {
            if let Ok(text) = std::fs::read_to_string(self.dir.join(name)) {
                loaded.insert(name.to_owned(), text);
            }
        }
    }

    fn on_disk(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(name)).ok()
    }

    fn property(&self, name: &str, key: &str) -> String {
        let loaded = self.loaded.lock().unwrap().get(name).cloned();
        match key {
            "LoadState" => if loaded.is_some() {
                "loaded"
            } else {
                "not-found"
            }
            .into(),
            "FragmentPath" => loaded
                .as_ref()
                .map(|_| self.dir.join(name).display().to_string())
                .unwrap_or_default(),
            "NeedDaemonReload" => if loaded != self.on_disk(name) {
                "yes"
            } else {
                "no"
            }
            .into(),
            "OnFailure" => {
                // As systemd reads it: each line adds, an empty value clears; drop-ins are not modelled.
                let mut units: Vec<String> = Vec::new();
                let mut section = "";
                for line in loaded.unwrap_or_default().lines().map(str::trim) {
                    if line.starts_with('[') {
                        section = if line == "[Unit]" { "unit" } else { "" };
                    } else if let Some(value) = line
                        .strip_prefix("OnFailure=")
                        .filter(|_| section == "unit")
                    {
                        if value.trim().is_empty() {
                            units.clear();
                        }
                        units.extend(value.split_whitespace().map(str::to_owned));
                    }
                }
                units.join(" ")
            }
            other => panic!("unexpected property {other}"),
        }
    }

    /// Answers `systemctl show` (with `--property=` and maybe `--value`) and `daemon-reload`; `None` for
    /// anything else, which the caller handles.
    pub fn answer(&self, args: &[&str]) -> Option<Result<String, String>> {
        match args {
            ["daemon-reload"] => {
                self.reload();
                Some(Ok(String::new()))
            }
            ["show", rest @ ..] => {
                let keys: Vec<&str> = rest
                    .iter()
                    .filter_map(|a| a.strip_prefix("--property="))
                    .collect();
                let modelled = ["OnFailure", "LoadState", "FragmentPath", "NeedDaemonReload"];
                if keys.is_empty() || !keys.iter().all(|k| modelled.contains(k)) {
                    return None;
                }
                let value_only = rest.contains(&"--value");
                let units: Vec<&str> = rest
                    .iter()
                    .copied()
                    .filter(|a| !a.starts_with("--"))
                    .collect();
                let blocks: Vec<String> = units
                    .iter()
                    .map(|unit| {
                        keys.iter()
                            .map(|key| {
                                let value = self.property(unit, key);
                                if value_only {
                                    value
                                } else {
                                    format!("{key}={value}")
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .collect();
                Some(Ok(blocks.join(if value_only { "\n" } else { "\n\n" })))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
impl Systemd for LoadedUnits {
    fn unavailable(&self) -> Option<String> {
        None
    }
    fn systemctl(&self, args: &[&str]) -> Result<String, String> {
        self.answer(args)
            .unwrap_or_else(|| Err(format!("unexpected systemctl call: {args:?}")))
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

    #[test]
    fn memory_and_task_limits_bound_the_agent_but_never_the_rollback() {
        // #182: a leak or a runaway loop is stopped in the agent's own cgroup, far above what it uses.
        // No swap, so MemoryMax is the real ceiling; systemd stops the whole unit on an OOM kill, so
        // Restart= and OnFailure= (ADR 0030) take over as for any failure.
        for unit_values in [values, recovery_values] {
            // No MemoryHigh= (owner, 2026-11-18): a leak is killed and restarted, not slowed down.
            assert!(unit_values("MemoryHigh").is_empty());
            assert_eq!(unit_values("MemoryMax"), ["128M"]);
            assert_eq!(unit_values("MemorySwapMax"), ["0"]);
            assert_eq!(unit_values("OOMPolicy"), ["stop"]);
            assert_eq!(unit_values("TasksMax"), ["64"]);
        }
        // The rollback unit is the step a limit must never stop (it acts once the service has failed,
        // possibly because the service hit its limit).
        for key in [
            "MemoryHigh",
            "MemoryMax",
            "MemorySwapMax",
            "TasksMax",
            "OOMPolicy",
        ] {
            assert!(
                !ROLLBACK_UNIT
                    .lines()
                    .any(|l| l.starts_with(&format!("{key}="))),
                "the rollback unit sets {key}="
            );
        }
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
    fn recovery_mode_is_covered_only_as_systemd_has_loaded_the_installers_units() {
        // #232, review of #235: what heartbeats report as `units.recovery`, from what systemd runs.
        let dir = crate::test_support::TempDir::new();
        let units = dir.path("units");
        std::fs::create_dir_all(&units).unwrap();
        let systemd = LoadedUnits::new(units.clone());
        let write = |name: &str, text: &str| std::fs::write(units.join(name), text).unwrap();
        let covered = || recovery_covered(&units, &systemd);
        // Nothing installed, then only the service.
        assert_eq!(covered(), Ok(false));
        write(UNIT_NAME, UNIT);
        systemd.reload();
        assert_eq!(covered(), Ok(false));
        // This release's units, written but not reloaded yet: systemd still runs the old settings.
        write(RECOVERY_UNIT_NAME, RECOVERY_UNIT);
        assert_eq!(covered(), Ok(false));
        systemd.reload();
        assert_eq!(covered(), Ok(true));
        // A service from before recovery mode: OnFailure= names only the rollback unit.
        let old = UNIT.replace(
            &format!("OnFailure={ROLLBACK_UNIT_NAME} {RECOVERY_UNIT_NAME}"),
            &format!("OnFailure={ROLLBACK_UNIT_NAME}"),
        );
        assert_ne!(old, UNIT);
        write(UNIT_NAME, &old);
        systemd.reload();
        assert_eq!(covered(), Ok(false));
        // The files are new again but systemd was not reloaded (the reviewer's case): not covered until it is.
        write(UNIT_NAME, UNIT);
        assert_eq!(covered(), Ok(false));
        systemd.reload();
        assert_eq!(covered(), Ok(true));
        // A recovery unit someone wrote by hand is not the installer's.
        write(
            RECOVERY_UNIT_NAME,
            &RECOVERY_UNIT.replacen(UNIT_MARKER, "# my copy", 1),
        );
        systemd.reload();
        assert_eq!(covered(), Ok(false));
        // systemctl cannot answer: an error, not a guess.
        write(RECOVERY_UNIT_NAME, RECOVERY_UNIT);
        let (_d, broken) = fake("exit 1", Duration::from_secs(5));
        assert!(recovery_covered(&units, &broken).is_err());
        // A file that is not a regular one is an error, and a FIFO does not block (review of #235).
        std::fs::remove_file(units.join(RECOVERY_UNIT_NAME)).unwrap();
        let fifo =
            std::ffi::CString::new(units.join(RECOVERY_UNIT_NAME).to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let error = covered().unwrap_err();
        assert!(error.contains("is not a regular file"), "{error}");
        std::fs::remove_file(units.join(RECOVERY_UNIT_NAME)).unwrap();
        std::fs::create_dir(units.join(RECOVERY_UNIT_NAME)).unwrap();
        assert!(covered().unwrap_err().contains(RECOVERY_UNIT_NAME));
    }

    #[test]
    fn systemd_analyze_verify_passes_these_units_and_refuses_one_systemd_cannot_load() {
        // Review of #235: the check `install --refresh-units` runs before it writes. Skipped where
        // systemd-analyze is not installed (it is on every CI runner and Debian).
        if !Path::new(SYSTEMD_ANALYZE).exists() {
            return;
        }
        let dir = crate::test_support::TempDir::new();
        let files: Vec<PathBuf> = [
            (UNIT_NAME, UNIT),
            (ROLLBACK_UNIT_NAME, ROLLBACK_UNIT),
            (RECOVERY_UNIT_NAME, RECOVERY_UNIT),
        ]
        .iter()
        .map(|(name, text)| {
            let text = text
                .replace("/usr/lib/fleet-agent/current/fleet-agent", "/bin/true")
                .replace("/usr/lib/fleet-agent/previous/fleet-agent", "/bin/true");
            dir.write(name, &text)
        })
        .collect();
        let systemctl = Systemctl::default();
        assert_eq!(systemctl.verify(&files).map(drop), Ok(()));
        // A unit systemd would refuse to start: its command is not an absolute path.
        let bad = dir.write("broken.service", "[Service]\nExecStart=fleet-agent run\n");
        let error = systemctl.verify(&[bad]).unwrap_err();
        assert!(error.contains("broken.service"), "{error}");
    }

    #[test]
    fn coverage_is_read_through_the_real_systemctl_runner() {
        // Review of #235, found by the update smoke test: the runner joins systemctl's lines with spaces, so
        // the answer must be read the way it arrives. A scripted systemctl prints what systemd 255 prints.
        let dir = crate::test_support::TempDir::new();
        let units = dir.path("units");
        std::fs::create_dir_all(&units).unwrap();
        std::fs::write(units.join(RECOVERY_UNIT_NAME), RECOVERY_UNIT).unwrap();
        let fragment = units.join(RECOVERY_UNIT_NAME);
        let script = |reload: &str| {
            format!(
                "case \"$*\" in\n\
                 *{UNIT_NAME}) printf 'OnFailure={ROLLBACK_UNIT_NAME} {RECOVERY_UNIT_NAME}\\nNeedDaemonReload=no\\n' ;;\n\
                 *{RECOVERY_UNIT_NAME}) printf 'LoadState=loaded\\nFragmentPath={}\\nNeedDaemonReload={reload}\\n' ;;\n\
                 *) exit 1 ;;\n\
                 esac",
                fragment.display()
            )
        };
        let (_d, systemctl) = fake(&script("no"), Duration::from_secs(5));
        assert_eq!(recovery_covered(&units, &systemctl), Ok(true));
        let (_d, systemctl) = fake(&script("yes"), Duration::from_secs(5));
        assert_eq!(recovery_covered(&units, &systemctl), Ok(false));
        // NeedDaemonReload for three units, one per line, arrives as one line too.
        let (_d, systemctl) = fake("printf 'no\\nno\\nno\\n'", Duration::from_secs(5));
        assert!(!needs_reload(&systemctl));
        let (_d, systemctl) = fake("printf 'no\\nyes\\nno\\n'", Duration::from_secs(5));
        assert!(needs_reload(&systemctl));
    }

    #[test]
    fn a_reload_is_needed_until_systemd_has_read_the_files() {
        let dir = crate::test_support::TempDir::new();
        let systemd = LoadedUnits::new(dir.path(""));
        std::fs::write(dir.path(UNIT_NAME), UNIT).unwrap();
        assert!(needs_reload(&systemd));
        systemd.reload();
        assert!(!needs_reload(&systemd));
        let (_d, broken) = fake("exit 1", Duration::from_secs(5));
        assert!(needs_reload(&broken), "when systemctl cannot say, reload");
    }

    fn fake(script: &str, timeout: Duration) -> (crate::test_support::TempDir, Systemctl) {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_support::TempDir::new();
        let path = dir.write("systemctl", &format!("#!/bin/sh\n{script}\n"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, Systemctl { path, timeout })
    }

    #[test]
    fn the_runner_reads_without_threads_and_a_descendant_holding_the_pipe_does_not_hold_it_up() {
        // Re-review of #235: the pipes are read from the calling thread (the soak counts threads). A command
        // that leaves a descendant with its output open still returns once it exits, with what it wrote.
        let (_dir, systemctl) = fake(
            "printf 'first\\n'; sleep 5 & printf 'last\\n'",
            Duration::from_secs(20),
        );
        let started = Instant::now();
        assert_eq!(systemctl.systemctl(&["show"]).unwrap(), "first last");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        // Written slowly, in pieces, while it runs.
        let (_dir, systemctl) = fake(
            "for i in 1 2 3; do printf \"$i \"; sleep 0.1; done",
            Duration::from_secs(20),
        );
        assert_eq!(systemctl.systemctl(&["show"]).unwrap(), "1 2 3");
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
