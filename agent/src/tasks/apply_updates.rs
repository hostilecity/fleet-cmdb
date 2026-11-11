//! The `apply_package_updates` task (P3-AGENT-UPDATES, FR-3.1, FR-3.3, AC-3.4, AC-3.5) under DEC-16's
//! policy: update the package index, then upgrade only (no removals, no new packages, no distribution
//! upgrade), non-interactively, keeping local configuration and package holds, with a bounded wait
//! for the package manager's lock. It never reboots and never restarts a service: it reports whether
//! a reboot is needed and which services run old code, then asks for a package report so the
//! dashboard shows the new versions and findings resolve.
//!
//! **What runs.** The task has no parameters (DEC-16). The job:
//!
//! 1. Lists the installed packages (dpkg, in the agent, read-only: [`crate::packages`]).
//! 2. Waits up to [`LOCK_WAIT`] while another program holds one of the package manager's locks
//!    (unattended-upgrades, apt-daily, an administrator), then fails `lock_timeout` with nothing run.
//! 3. Step 1, `apt-get update`; step 2, `apt-get upgrade` ([`apt`] for the exact vectors and why each
//!    option is there). Each runs in its own transient unit outside the agent's sandbox
//!    (`package_manager`, [`super::executor::unit`]). A lock taken by another program between the
//!    check and the step fails it with apt's lock message, read as `lock_timeout`.
//! 4. Lists the packages again: the difference is what was upgraded.
//! 5. Step 3, a simulation that changes nothing, for what `upgrade` held back (holds, or upgrades that
//!    would need a new package); step 4, `needrestart` in list mode when the VM has it, for the
//!    services running old code and the kernel.
//! 6. `reboot_required`: the Debian flag file, a kernel newer than the running one (needrestart), or
//!    an upgraded kernel package. Then a package report is requested ([`PackageReport`]).
//!
//! The agent writes `$ <program>` before each step's output, and a summary at the end.
//!
//! **Not interruptible** (catalog, DEC-14): a cancel is recorded by the server and the task runs on.
//! At its deadline (60 minutes) the unit is stopped (`SIGTERM`, then `SIGKILL` 60 seconds later) and
//! the result says the dpkg database may need `dpkg --configure -a` (DEC-16). If the agent stops
//! while a step runs, the step runs on in its unit; when the agent starts again it waits for it and
//! [`ApplyUpdates::recovered`] decides the outcome from the units' exits: an upgrade that ended with 0
//! is `succeeded` (threat model L8), without the lists only the finished job knows.
//!
//! **Other distributions** (issue #163): everything apt-specific is behind [`Manager`] ([`apt::Apt`]);
//! this file only runs steps and reads their results.

pub mod apt;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::executor::{Exit, Finish, Job, Program, Run, Stop, TaskImpl};
use super::ledger::Outcome;
use super::settings::TaskSettings;
use crate::shutdown::Shutdown;

/// The catalog type id.
pub const TYPE_ID: &str = "apply_package_updates";

/// How long the task waits for another program to release the package manager's locks before
/// failing with `lock_timeout` (D3). apt itself then waits as long again for the dpkg lock
/// (`DPkg::Lock::Timeout`), should another program take it in between.
pub const LOCK_WAIT: Duration = Duration::from_secs(300);

/// How often the locks are looked at while waiting.
const LOCK_POLL: Duration = Duration::from_secs(5);

/// The step number of the upgrade's transient unit (`fleet-agent-task-<id>-2.service`); step 1 is
/// the index refresh, 3 and 4 only read.
pub const UPGRADE_STEP: u32 = 2;

/// The most packages named in the summary line of the output; the rest are counted.
const NAMED_IN_SUMMARY: usize = 40;

/// The contract's limits on `services_needing_restart` and `packages_held_back`.
const MAX_SERVICES: usize = 64;
const MAX_HELD_BACK: usize = 64;

/// What one package manager runs and how its output reads (issue #163: one implementation per
/// manager). Every program is fixed in the implementation: nothing from the task reaches it.
pub trait Manager: Send + Sync {
    /// Whether this host uses this manager.
    fn present(&self, system: &dyn System) -> bool;
    /// The lock files the manager's programs take.
    fn locks(&self) -> &'static [&'static str];
    /// Refreshes the package index.
    fn refresh(&self) -> Program;
    /// Upgrades under the DEC-16 policy.
    fn upgrade(&self) -> Program;
    /// A simulation, changing nothing, of what is still upgradable.
    fn pending(&self) -> Program;
    fn read_pending(&self, output: &str) -> Vec<String>;
    /// A check of services running old code, if the host has one.
    fn restart_check(&self, system: &dyn System) -> Option<Program>;
    fn read_restart_check(&self, output: &str) -> RestartCheck;
    /// Whether a program failed because another program held a lock.
    fn lock_failure(&self, output: &str) -> bool;
    /// Whether the output says an earlier run was interrupted and the database needs repair.
    fn needs_repair(&self, output: &str) -> bool;
    /// The repair command, for the operator (never run by the agent).
    fn repair(&self) -> &'static str;
    /// The file that, when present, says a reboot is needed.
    fn reboot_flag(&self) -> &'static str;
    /// Whether upgrading `package` (a name, maybe with `:arch`) needs a reboot to take effect.
    fn is_kernel(&self, package: &str) -> bool;
}

/// What a restart check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestartCheck {
    /// Service units running old code, sorted, each once.
    pub services: Vec<String>,
    /// Whether a newer kernel is installed than runs; `None` if the check could not tell.
    pub kernel_pending: Option<bool>,
}

/// What the task reads of the host, behind a trait so the tests can script it.
pub trait System: Send + Sync {
    /// The installed packages, `name:architecture` to version, or why they could not be listed.
    fn installed(&self, stop: &Shutdown) -> Result<BTreeMap<String, String>, String>;
    fn exists(&self, path: &str) -> bool;
    /// Whether another process holds a lock on `path` (an `fcntl` record lock, as apt and dpkg take).
    fn locked(&self, path: &str) -> bool;
}

/// Asks the agent's package report loop for a report now (P2-A04), as the server's on-demand request
/// does (DEC-13).
pub trait PackageReport: Send + Sync {
    fn request_package_report(&self);
}

/// A [`PackageReport`] that asks for nothing (tests).
#[cfg(test)]
pub struct Ignored;

#[cfg(test)]
impl PackageReport for Ignored {
    fn request_package_report(&self) {}
}

/// The real host.
pub struct RealSystem;

impl System for RealSystem {
    fn installed(&self, stop: &Shutdown) -> Result<BTreeMap<String, String>, String> {
        match crate::packages::collect(&crate::facts::host::RealHost::new(), Some(stop)) {
            crate::packages::Collected::Dpkg(listing) => Ok(listing
                .packages
                .into_iter()
                .map(|p| (format!("{}:{}", p.name, p.architecture), p.version))
                .collect()),
            crate::packages::Collected::Unsupported(why)
            | crate::packages::Collected::Unreadable(why) => Err(why),
            crate::packages::Collected::Stopping => Err("the agent is stopping".into()),
        }
    }

    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn locked(&self, path: &str) -> bool {
        // Opened read-only (the agent's file system is): F_GETLK needs no write access. A missing file
        // is not held.
        let Ok(file) = std::fs::File::open(path) else {
            return false;
        };
        lock_held(&file)
    }
}

/// Whether a process other than this one holds a lock that conflicts with a write lock on `file`.
pub fn lock_held(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: fcntl(F_GETLK) on an open descriptor only fills in the zeroed flock structure.
    unsafe {
        let mut lock: libc::flock = std::mem::zeroed();
        lock.l_type = libc::F_WRLCK as libc::c_short;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        lock.l_start = 0;
        lock.l_len = 0;
        libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) == 0
            && lock.l_type != libc::F_UNLCK as libc::c_short
    }
}

/// The task type.
pub struct ApplyUpdates {
    manager: Arc<dyn Manager>,
    system: Arc<dyn System>,
    reports: Arc<dyn PackageReport>,
    lock_wait: Duration,
}

impl ApplyUpdates {
    /// apt on the real host.
    pub fn production(reports: Arc<dyn PackageReport>) -> Self {
        Self::new(Arc::new(apt::Apt), Arc::new(RealSystem), reports, LOCK_WAIT)
    }

    pub fn new(
        manager: Arc<dyn Manager>,
        system: Arc<dyn System>,
        reports: Arc<dyn PackageReport>,
        lock_wait: Duration,
    ) -> Self {
        Self {
            manager,
            system,
            reports,
            lock_wait,
        }
    }

    fn repair_note(&self) -> String {
        format!(
            "the package database may need repair: run {} as root on this VM, then apply package updates again; packages upgraded before the stop stay upgraded",
            self.manager.repair()
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

impl TaskImpl for ApplyUpdates {
    fn type_id(&self) -> &'static str {
        TYPE_ID
    }

    fn prepare(&self, parameters: &Value, _: &TaskSettings) -> Result<Box<dyn Job>, &'static str> {
        let _: NoParams = super::executor::parse(parameters)?;
        if !self.manager.present(&*self.system) {
            // Debian only (DEC-01): a host without apt runs nothing.
            return Err("not_supported");
        }
        Ok(Box::new(UpdateJob {
            manager: Arc::clone(&self.manager),
            system: Arc::clone(&self.system),
            reports: Arc::clone(&self.reports),
            lock_wait: self.lock_wait,
            repair_note: self.repair_note(),
        }))
    }

    fn recovered(
        &self,
        steps: &[(u32, Exit)],
        timed_out: bool,
        output: &str,
        notes: &mut Vec<String>,
    ) -> Option<Finish> {
        let upgrade_started = steps.iter().any(|(step, _)| *step >= UPGRADE_STEP);
        if upgrade_started {
            self.reports.request_package_report();
        }
        if timed_out {
            if upgrade_started {
                notes.push(self.repair_note());
            }
            return None;
        }
        // A step that failed ended the job there; the steps after the upgrade only read.
        if let Some((step, exit)) = steps
            .iter()
            .find(|(step, exit)| *step <= UPGRADE_STEP && !exit.success())
        {
            let reason = if self.manager.lock_failure(output) {
                "lock_timeout"
            } else {
                "nonzero_exit"
            };
            if (*step == UPGRADE_STEP && reason != "lock_timeout")
                || self.manager.needs_repair(output)
            {
                notes.push(self.repair_note());
            }
            return Some(Finish {
                outcome: Outcome::Failed,
                reason: Some(reason),
                exit_status: exit.code,
                details: Map::new(),
            });
        }
        if !upgrade_started {
            // Only the index was refreshed: nothing was upgraded, and the job did not finish.
            return None;
        }
        // The upgrade ended with 0 (a later step exists only after a successful upgrade). What the job
        // would have listed afterwards is not known; the package report that follows shows the versions.
        let reboot = self.system.exists(self.manager.reboot_flag());
        notes.push(format!(
            "the upgrade finished while the agent was restarting; the upgraded and held back packages and the services using old code were not listed, and the package report that follows shows the new versions; reboot required: {}",
            if reboot { "yes" } else { "not flagged" }
        ));
        let mut details = Map::new();
        details.insert("reboot_required".into(), json!(reboot));
        Some(Finish {
            outcome: Outcome::Succeeded,
            reason: None,
            exit_status: Some(0),
            details,
        })
    }
}

struct UpdateJob {
    manager: Arc<dyn Manager>,
    system: Arc<dyn System>,
    reports: Arc<dyn PackageReport>,
    lock_wait: Duration,
    repair_note: String,
}

impl UpdateJob {
    /// Waits while a lock is held. `Ok(Some(path))`: still held after the wait.
    fn wait_for_locks(&self, run: &mut Run<'_>) -> Result<Option<&'static str>, Stop> {
        let until = Instant::now() + self.lock_wait;
        let mut said = false;
        loop {
            let Some(held) = self
                .manager
                .locks()
                .iter()
                .copied()
                .find(|path| self.system.locked(path))
            else {
                return Ok(None);
            };
            if Instant::now() >= until {
                return Ok(Some(held));
            }
            if !said {
                run.print(&format!(
                    "[fleet-agent: another program holds {held}; waiting up to {} seconds for it]",
                    self.lock_wait.as_secs()
                ));
                said = true;
            }
            run.pause(LOCK_POLL.min(until.saturating_duration_since(Instant::now())))?;
        }
    }

    /// The finish of a failed step: `lock_timeout` when another program held a lock.
    fn failed(&self, run: &mut Run<'_>, exit: Exit, output: &str, upgrading: bool) -> Finish {
        let lock = self.manager.lock_failure(output);
        if lock {
            run.note("another program held the package manager's lock; nothing more was run. Often an automatic update is running: wait and try again");
        }
        // An upgrade refused for a lock changed nothing; any other failed upgrade may have left dpkg
        // half done.
        if (upgrading && !lock) || self.manager.needs_repair(output) {
            run.note(&self.repair_note);
        }
        let mut finish = Finish::from_exit(exit);
        if lock {
            finish.reason = Some("lock_timeout");
        }
        finish
    }

    fn installed(&self, run: &mut Run<'_>) -> Option<BTreeMap<String, String>> {
        // A listing may take up to its own limit; it never runs past the task's deadline.
        if run.remaining() < crate::packages::TIMEOUT {
            run.note("the installed packages were not listed: too little time was left before the deadline");
            return None;
        }
        match self.system.installed(run.shutdown()) {
            Ok(packages) => Some(packages),
            Err(why) => {
                run.note(&format!(
                    "the installed packages could not be listed: {why}"
                ));
                None
            }
        }
    }
}

impl Job for UpdateJob {
    fn run(&self, run: &mut Run<'_>) -> Result<Finish, Stop> {
        let before = self.installed(run);

        if let Some(held) = self.wait_for_locks(run)? {
            run.note(&format!(
                "the package manager is busy: another program held {held} for {} seconds, so nothing was run and nothing was upgraded. Often an automatic update is running: wait and try again",
                self.lock_wait.as_secs()
            ));
            return Ok(Finish {
                outcome: Outcome::Failed,
                reason: Some("lock_timeout"),
                exit_status: None,
                details: Map::new(),
            });
        }

        let refresh = self.manager.refresh();
        run.heading(&refresh);
        let (exit, output, _) = run.program_output(&refresh)?;
        if !exit.success() {
            return Ok(self.failed(run, exit, &output, false));
        }

        let upgrade = self.manager.upgrade();
        run.heading(&upgrade);
        let upgraded = run.program_output(&upgrade);
        // From here packages may have changed, however the step ended.
        self.reports.request_package_report();
        let (exit, output, _) = match upgraded {
            Ok(ran) => ran,
            Err(Stop::TimedOut) => {
                run.note(&self.repair_note);
                return Err(Stop::TimedOut);
            }
            Err(stop) => return Err(stop),
        };
        if !exit.success() {
            return Ok(self.failed(run, exit, &output, true));
        }

        let after = self.installed(run);
        let upgraded: Option<Vec<String>> = before.as_ref().zip(after.as_ref()).map(|(b, a)| {
            a.iter()
                .filter(|(key, version)| b.get(*key).is_some_and(|old| old != *version))
                .map(|(key, _)| display_name(key))
                .collect()
        });

        // What was held back: a simulation, changing nothing. Its failure fails nothing.
        let pending = self.manager.pending();
        run.heading(&pending);
        // Output that was cut may lack some of the packages: then the list is not known.
        let held_back = match run.program_output(&pending) {
            Ok((exit, output, false)) if exit.success() => Some(self.manager.read_pending(&output)),
            Ok(_) => None,
            Err(Stop::Failed(_)) => None,
            Err(stop) => return Err(stop),
        };

        let check = match self.manager.restart_check(&*self.system) {
            Some(program) => {
                run.heading(&program);
                match run.program_output(&program) {
                    Ok((exit, output, false)) if exit.success() => {
                        Some(self.manager.read_restart_check(&output))
                    }
                    Ok(_) | Err(Stop::Failed(_)) => None,
                    Err(stop) => return Err(stop),
                }
            }
            None => None,
        };

        let flag = self.system.exists(self.manager.reboot_flag());
        let kernel_upgraded = upgraded
            .iter()
            .flatten()
            .any(|name| self.manager.is_kernel(name));
        let kernel_pending = check.as_ref().and_then(|c| c.kernel_pending) == Some(true);
        let reboot = flag || kernel_upgraded || kernel_pending;

        let mut details = Map::new();
        details.insert("reboot_required".into(), json!(reboot));
        if let Some(upgraded) = &upgraded {
            details.insert("packages_upgraded".into(), json!(upgraded.len()));
        }
        if let Some(held_back) = &held_back {
            let mut held_back = held_back.clone();
            held_back.truncate(MAX_HELD_BACK);
            details.insert("packages_held_back".into(), json!(held_back));
        }
        if let Some(check) = &check {
            let mut services = check.services.clone();
            services.truncate(MAX_SERVICES);
            details.insert("services_needing_restart".into(), json!(services));
        }

        // The summary, after the output.
        match &upgraded {
            Some(names) if names.is_empty() => run.note("no package was upgraded"),
            Some(names) => run.note(&format!(
                "{} upgraded: {}",
                count(names.len(), "package"),
                listed(names)
            )),
            None => run.note("which packages were upgraded is not known (see above); the package report that follows shows the versions"),
        }
        match &held_back {
            Some(names) if names.is_empty() => {}
            Some(names) => run.note(&format!(
                "{} held back (on hold, or the upgrade needs a new package or a removal), not upgraded: {}",
                count(names.len(), "package"),
                listed(names)
            )),
            None => run.note(
                "which packages were held back is not known: the simulation failed or printed too much",
            ),
        }
        let mut why = Vec::new();
        if flag {
            why.push(format!("{} exists", self.manager.reboot_flag()));
        }
        if kernel_upgraded {
            why.push("a kernel package was upgraded".to_owned());
        }
        if kernel_pending {
            why.push("a newer kernel is installed than the one running".to_owned());
        }
        if reboot {
            run.note(&format!(
                "reboot required ({}); the task never reboots",
                why.join(", ")
            ));
        } else {
            run.note("no reboot required");
        }
        match &check {
            Some(check) if check.services.is_empty() => run.note("no service runs old code"),
            Some(check) => run.note(&format!(
                "services using old code, not restarted (the task never restarts services): {}",
                listed(&check.services)
            )),
            None if self.manager.restart_check(&*self.system).is_some() => {
                run.note("the restart check failed or printed too much, so services using old code are not known")
            }
            None => {
                run.note("needrestart is not installed, so services using old code are not known")
            }
        }
        Ok(Finish {
            outcome: Outcome::Succeeded,
            reason: None,
            exit_status: exit.code,
            details,
        })
    }
}

/// `name:arch` as a person reads it: the bare name for `all` and this host's own architecture.
fn display_name(key: &str) -> String {
    match key.split_once(':') {
        Some((name, arch)) if arch == "all" || arch == native_arch() => name.to_owned(),
        _ => key.to_owned(),
    }
}

/// dpkg's name of this build's architecture.
fn native_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "i386",
        "arm" => "armhf",
        other => other,
    }
}

fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Names for a summary line: at most [`NAMED_IN_SUMMARY`], then how many more.
fn listed(names: &[String]) -> String {
    let mut text = names
        .iter()
        .take(NAMED_IN_SUMMARY)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > NAMED_IN_SUMMARY {
        text.push_str(&format!(", and {} more", names.len() - NAMED_IN_SUMMARY));
    }
    text
}

#[cfg(test)]
mod tests;
