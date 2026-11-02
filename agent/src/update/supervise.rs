//! The supervisor: installs a staged release, switches to it, and goes back if it does not confirm
//! (P1-A12, ADR 0018).
//!
//! It runs as `fleet-agent update-supervise`, started with `systemd-run` as a transient unit outside
//! the agent's sandbox, from the version being **replaced** (the known-good one): a new binary that
//! cannot start cannot be trusted to roll itself back. The server never reaches it: it takes no
//! arguments but the config path, and reads what to do from the update record the agent staged.
//!
//! ```text
//! Staged ─▶ Switching ─▶ Switched ─▶ Confirmed ─▶ (record removed)
//!    │          │            │
//!    └─ failed ─┘            └─ no confirmation by the deadline, the service failed, or a crash loop
//!       (reported `failed`)        ▼
//!                             RollingBack ─▶ (record removed; reported `rolled_back`)
//! ```
//!
//! Every step can be repeated, and the phase is written to the update record before the step it
//! announces, so a supervisor that is killed is resumed from the same place, by the agent's watchdog
//! (a timer of its own, and a check at startup) or by the failure hook, and ends with exactly one
//! working version. A VM that restarts during an update is handled as ADR 0018 says: an update the VM
//! restarted under is never confirmed, so it is rolled back (or, before the switch, reported failed).
//! Otherwise: `current` is swapped atomically, by renaming a link, and only the
//! supervisor moves it. The supervisor holds an exclusive lock for as long as it runs, so there is never
//! more than one.
//!
//! The new version confirms by writing the marker after the first heartbeat the server acknowledged
//! (authenticated with its credential). Only the supervisor decides what a missing marker means.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::layout::{
    LOCK_FILE, Layout, MARKER_FILE, RECORD_FILE, RESULT_FILE, SUPERVISOR_UNIT, free_bytes,
    link_version, parse_version,
};
use super::record::{Marker, Outcome, PendingResult, Phase, Record, StateFile, reason};
use super::stage;
use crate::fsx::{self, Lock};
use crate::install::{Systemd, UNIT_NAME};
use crate::release::ReleaseKey;
use crate::report::rfc3339;

/// Room to leave on the disk holding the versions, beyond the binary itself.
const FREE_SPACE_MARGIN: u64 = 4 * 1024 * 1024;

/// A state record larger than this is not copied into the backup (the records are a few KiB).
const MAX_BACKUP_FILE: u64 = 1024 * 1024;

/// How long past its own deadline a supervisor may keep the lock before the failure hook stops it.
/// A working supervisor rolls back within seconds of its deadline; one that is still holding the lock
/// a minute later is hung (stuck in a `systemctl` call, say) and must not block the rollback.
/// The rollback unit's `TimeoutStartSec=` (4000 s) covers the longest deadline (3600 s) plus two of these.
pub const OVERDUE_GRACE: Duration = Duration::from_secs(60);

/// Time, so tests need not wait.
pub trait Clock {
    fn now(&self) -> SystemTime;
    fn sleep(&self, duration: Duration);
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

pub fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Why the supervisor was started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// Carry the update in the record on from wherever it got to.
    Resume,
    /// Go back, if an update has switched and not confirmed: the unit's `OnFailure=` hook, because the
    /// new version kept failing.
    Rollback(&'static str),
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// No update in progress, or none that this intent concerns.
    NothingToDo,
    /// Another supervisor holds the lock and is handling it.
    Busy,
    /// The new version confirmed; the update is complete.
    Confirmed,
    /// The new version was replaced by the previous one again.
    RolledBack,
    /// The update stopped before the switch; nothing changed.
    Failed,
}

pub struct Supervisor<'a> {
    pub layout: &'a Layout,
    pub keys: &'a [ReleaseKey],
    pub systemd: &'a dyn Systemd,
    pub clock: &'a dyn Clock,
    /// The version of this binary, which must be the version the update replaces.
    pub running: &'a semver::Version,
    /// How often to look for the marker and the state of the service.
    pub poll: Duration,
    /// The kernel's id of this boot ([`super::layout::boot_id`]).
    pub boot_id: Option<String>,
    /// Swaps `current` (`fsx::replace_symlink`; a test can make it fail after the rename).
    pub swap_current: fn(&Path, &Path) -> io::Result<()>,
}

/// How long an update may wait between being staged and the switch before it is abandoned.
pub const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Why a switch did not complete.
#[derive(Debug, PartialEq, Eq)]
enum SwitchError {
    /// `current` still points to the version being replaced: nothing was switched.
    NotSwitched(String),
    /// `current` cannot be read: whether the switch happened is unknown, so nothing is cleaned up.
    Unknown(String),
}

/// After a failed swap of `current`, what actually happened. The rename that swaps the link can succeed
/// and the sync of its directory fail afterwards; then the new version is selected, and the update must
/// go on as a switched one (rolled back if it does not confirm), not be cleaned up as though nothing had
/// changed.
fn classify_switch_failure(layout: &Layout, rec: &Record, error: &str) -> Result<(), SwitchError> {
    match link_version(&layout.current()) {
        Some(v) if v == rec.version => {
            tracing::warn!(
                "the switch to {} took effect but did not complete cleanly ({error}); carrying on as switched",
                rec.version
            );
            Ok(())
        }
        Some(v) if v == rec.from_version => Err(SwitchError::NotSwitched(format!(
            "cannot switch to the new version: {error}"
        ))),
        _ => Err(SwitchError::Unknown(format!(
            "cannot switch to the new version ({error}), and `current` cannot be read; the update record is kept for the next supervisor"
        ))),
    }
}

impl Supervisor<'_> {
    pub fn run(&self, intent: Intent) -> Result<Ended, String> {
        let state = &self.layout.state_dir;
        let lock = match intent {
            Intent::Resume => self.try_lock()?,
            Intent::Rollback(_) => Some(self.lock_for_rollback()?),
        };
        let Some(_lock) = lock else {
            tracing::info!("another update supervisor is running; leaving the update to it");
            return Ok(Ended::Busy);
        };
        let mut rec = match Record::read(state) {
            Ok(Some(rec)) => rec,
            Ok(None) => {
                tracing::info!("no update is in progress");
                return Ok(Ended::NothingToDo);
            }
            Err(e) => {
                // Writes are atomic, so this is damage from outside; an unreadable record would
                // otherwise block every later update.
                let _ = Record::remove(state);
                return Err(format!(
                    "the update record is unusable and was removed: {e}"
                ));
            }
        };
        self.validate(&rec)?;
        let switched_now = link_version(&self.layout.current()).as_deref() == Some(&rec.version);
        let rebooted = rec.rebooted(self.boot_id.as_deref());
        if !rec.past_switch() && !switched_now {
            if rebooted {
                return self.fail_before_switch(
                    &rec,
                    "the VM restarted before the update switched to the new version",
                );
            }
            let age = unix(self.clock.now()).saturating_sub(rec.started_unix);
            if age > STALE_AFTER.as_secs() {
                return self.fail_before_switch(
                    &rec,
                    "the update did not reach the switch within 24 hours",
                );
            }
        } else if rebooted
            && matches!(
                rec.phase,
                Phase::Staged | Phase::Switching | Phase::Switched
            )
            && !self.confirmed(&rec)
        {
            // ADR 0018: an update the VM restarted under before it was confirmed is rolled back.
            self.to_rolling_back(
                &mut rec,
                "the VM restarted before the new version confirmed the update",
            )?;
        }
        if let Intent::Rollback(why) = intent {
            let switched = matches!(rec.phase, Phase::Switched | Phase::RollingBack)
                || link_version(&self.layout.current()).as_deref() == Some(&rec.version);
            if rec.phase == Phase::Confirmed || !switched || self.confirmed(&rec) {
                tracing::info!("no unconfirmed update is running; nothing to roll back");
                return Ok(Ended::NothingToDo);
            }
            if rec.phase != Phase::RollingBack {
                self.to_rolling_back(&mut rec, why)?;
            }
        }
        tracing::info!(
            rollout_id = rec.rollout_id,
            from = rec.from_version.as_str(),
            to = rec.version.as_str(),
            phase = ?rec.phase,
            "supervising the update"
        );
        loop {
            match rec.phase {
                Phase::Staged | Phase::Switching => match self.install_and_switch(&mut rec) {
                    // `current` points to the new version now: from here on the update is not
                    // `failed` but waiting for confirmation, whatever else goes wrong.
                    Ok(()) => self.switched(&mut rec)?,
                    Err(SwitchError::NotSwitched(why)) => {
                        return self.fail_before_switch(&rec, &why);
                    }
                    Err(SwitchError::Unknown(why)) => return Err(why),
                },
                Phase::Switched => {
                    if let Some(why) = self.await_confirmation(&mut rec)? {
                        self.to_rolling_back(&mut rec, &why)?;
                    }
                }
                Phase::RollingBack => {
                    self.roll_back(&mut rec)?;
                    return Ok(Ended::RolledBack);
                }
                Phase::Confirmed => {
                    self.finish_confirmed(&rec)?;
                    return Ok(Ended::Confirmed);
                }
            }
        }
    }

    fn try_lock(&self) -> Result<Option<Lock>, String> {
        let state = &self.layout.state_dir;
        Lock::file(&state.join(LOCK_FILE))
            .map_err(|e| format!("cannot take the update lock in {}: {e}", state.display()))
    }

    /// The lock, for the failure hook. Unlike a resumed supervisor, the hook does not give up when the
    /// lock is held: systemd starts it once per failure of the service, and the failure that starts it
    /// may be the last one (the start limit), so if it left and the holder then died, nothing would ever
    /// roll back. It waits instead. A supervisor that holds the lock is left to finish while it is within
    /// its own deadline plus [`OVERDUE_GRACE`]; after that it is hung and is killed (it is idempotent and
    /// writes ahead, so killing it at any point is safe), and the hook carries on from the record. There
    /// is still never more than one supervisor: the hook only proceeds once it holds the lock itself.
    fn lock_for_rollback(&self) -> Result<Lock, String> {
        let state = &self.layout.state_dir;
        let mut said = false;
        let mut killed_at = None;
        loop {
            if let Some(lock) = self.try_lock()? {
                return Ok(lock);
            }
            if !said {
                tracing::info!("an update supervisor holds the lock; waiting for it to finish");
                said = true;
            }
            let now = unix(self.clock.now());
            // No record (it is finishing) or an unreadable one: nothing to measure, just wait.
            let overdue_at = match Record::read(state) {
                Ok(Some(rec)) => Some(
                    rec.deadline_unix
                        .unwrap_or(rec.started_unix.saturating_add(rec.confirm_seconds))
                        .saturating_add(OVERDUE_GRACE.as_secs()),
                ),
                _ => None,
            };
            match (overdue_at, killed_at) {
                (Some(at), None) if now >= at => {
                    tracing::warn!(
                        "the update supervisor is past its deadline and still holds the lock; stopping it to roll back"
                    );
                    let unit = format!("{SUPERVISOR_UNIT}.service");
                    if let Err(e) =
                        self.systemd
                            .systemctl(&["kill", "--signal=SIGKILL", unit.as_str()])
                    {
                        tracing::warn!("cannot stop the update supervisor: {e}");
                    }
                    killed_at = Some(now);
                }
                (_, Some(at)) if now >= at.saturating_add(OVERDUE_GRACE.as_secs()) => {
                    return Err(format!(
                        "the update lock in {} is still held after the update supervisor was stopped; not rolling back",
                        state.display()
                    ));
                }
                _ => {}
            }
            self.clock.sleep(self.poll);
        }
    }

    fn validate(&self, rec: &Record) -> Result<(), String> {
        let (Some(to), Some(from)) = (
            parse_version(&rec.version),
            parse_version(&rec.from_version),
        ) else {
            return Err("the update record names a version that is not a release version".into());
        };
        if from != *self.running {
            return Err(format!(
                "this is version {}, but the update replaces {from}; the supervisor must run from the version being replaced",
                self.running
            ));
        }
        if to <= from {
            return Err(format!("version {to} is not newer than {from}"));
        }
        Ok(())
    }

    fn confirmed(&self, rec: &Record) -> bool {
        matches!(Marker::read(&self.layout.state_dir), Ok(Some(m)) if m.confirms(rec))
    }

    fn write(&self, rec: &Record) -> Result<(), String> {
        rec.write(&self.layout.state_dir)
            .map_err(|e| format!("cannot write the update record: {e}"))
    }

    /// Verifies the staged release again, installs it, backs up the state, and swaps `current`.
    /// `NotSwitched` means nothing was switched (or only `previous`, which is the version `current`
    /// already is).
    fn install_and_switch(&self, rec: &mut Record) -> Result<(), SwitchError> {
        let layout = self.layout;
        if link_version(&layout.current()).as_deref() == Some(&rec.version) {
            // Swapped already; the record had not caught up.
            return Ok(());
        }
        self.prepare_switch(rec).map_err(SwitchError::NotSwitched)?;
        rec.phase = Phase::Switching;
        self.write(rec).map_err(SwitchError::NotSwitched)?;
        let from_target = Path::new("versions").join(&rec.from_version);
        let to_target = Path::new("versions").join(&rec.version);
        if let Err(e) = fsx::replace_symlink(&layout.previous(), &from_target) {
            return Err(SwitchError::NotSwitched(format!(
                "cannot point `previous` to {}: {e}",
                rec.from_version
            )));
        }
        if let Err(e) = (self.swap_current)(&layout.current(), &to_target) {
            return classify_switch_failure(layout, rec, &e.to_string());
        }
        tracing::info!(
            version = rec.version.as_str(),
            "switched `current` to the new version"
        );
        Ok(())
    }

    /// Everything before the swap: verify, install, back up. Nothing is selected yet.
    fn prepare_switch(&self, rec: &Record) -> Result<(), String> {
        let layout = self.layout;
        let to = parse_version(&rec.version).ok_or("bad version")?;
        let current = link_version(&layout.current());
        if current.as_deref() != Some(&rec.from_version) {
            return Err(format!(
                "`current` points to {} instead of the version being replaced, {}",
                current.as_deref().unwrap_or("nothing readable"),
                rec.from_version
            ));
        }
        let staging = layout.staging(&rec.version);
        let manifest = stage::verify_staged(&staging, self.keys, &to, self.running)?;

        let versions = layout.versions_dir();
        let free = free_bytes(&versions)
            .map_err(|e| format!("cannot check the free space in {}: {e}", versions.display()))?;
        if free < manifest.size.saturating_add(FREE_SPACE_MARGIN) {
            return Err(format!(
                "not enough free space in {}: {} MiB needed, {} MiB free",
                versions.display(),
                (manifest.size + FREE_SPACE_MARGIN).div_ceil(1024 * 1024),
                free / (1024 * 1024)
            ));
        }
        let version_dir = layout.version_dir(&rec.version);
        match DirBuilder::new().mode(0o755).create(&version_dir) {
            Ok(()) => fs::set_permissions(&version_dir, fs::Permissions::from_mode(0o755)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
        .map_err(|e| format!("cannot create {}: {e}", version_dir.display()))?;
        let binary = layout.binary(&rec.version);
        let mut source = fs::File::open(staging.join(stage::BINARY_STAGED))
            .map_err(|e| format!("cannot read the staged binary: {e}"))?;
        fsx::write_atomic_from(&binary, &mut source, 0o755)
            .map_err(|e| format!("cannot install {}: {e}", binary.display()))?;
        // The installed file is the one that was verified.
        stage::check_file(&binary, &manifest)?;

        backup_state(layout).map_err(|e| format!("cannot back up the state: {e}"))
    }

    fn switched(&self, rec: &mut Record) -> Result<(), String> {
        rec.phase = Phase::Switched;
        rec.restarted = false;
        rec.deadline_unix = None;
        self.write(rec)
    }

    /// Restarts the service into the new version and waits for the marker. Returns `Ok(None)` after
    /// moving the record to `Confirmed`, and `Ok(Some(why))` when the update must be rolled back.
    fn await_confirmation(&self, rec: &mut Record) -> Result<Option<String>, String> {
        if self.confirmed(rec) {
            return self.to_confirmed(rec).map(|()| None);
        }
        if !rec.restarted {
            // A service stuck in `failed` refuses to start again until it is reset.
            let _ = self.systemd.systemctl(&["reset-failed", UNIT_NAME]);
            if let Err(e) = self.systemd.systemctl(&["restart", UNIT_NAME]) {
                return Ok(Some(format!(
                    "the service could not be restarted into the new version: {}",
                    crate::logging::sanitize(&e, 200)
                )));
            }
            rec.restarted = true;
            rec.deadline_unix = Some(unix(self.clock.now()) + rec.confirm_seconds);
            self.write(rec)?;
            tracing::info!(
                confirm_seconds = rec.confirm_seconds,
                "restarted the service; waiting for the new version to confirm"
            );
        }
        let deadline = rec
            .deadline_unix
            .unwrap_or_else(|| unix(self.clock.now()) + rec.confirm_seconds);
        loop {
            if self.confirmed(rec) {
                return self.to_confirmed(rec).map(|()| None);
            }
            let state = self.systemd.state();
            if state == "failed" {
                return Ok(Some(
                    "the new version failed to start or kept failing, and systemd stopped restarting it"
                        .into(),
                ));
            }
            if unix(self.clock.now()) >= deadline {
                return Ok(Some(format!(
                    "no acknowledged heartbeat from the new version within {} seconds of the switch",
                    rec.confirm_seconds
                )));
            }
            self.clock.sleep(self.poll);
        }
    }

    fn to_confirmed(&self, rec: &mut Record) -> Result<(), String> {
        rec.phase = Phase::Confirmed;
        self.write(rec)?;
        tracing::info!(version = rec.version.as_str(), "the new version confirmed");
        Ok(())
    }

    fn to_rolling_back(&self, rec: &mut Record, why: &str) -> Result<(), String> {
        tracing::warn!(reason = why, "rolling back to {}", rec.from_version);
        rec.phase = Phase::RollingBack;
        rec.restarted = false;
        rec.rollback_reason = Some(reason(why));
        self.write(rec)
    }

    /// Back to the previous version: stop the new one, then `current`, the state, the report, and the
    /// service, in that order. The new version is stopped first so nothing it still has in flight (an
    /// inventory report being saved, say) can overwrite the state after it was restored. Every step can
    /// be repeated, so a supervisor killed halfway is finished by the next.
    fn roll_back(&self, rec: &mut Record) -> Result<(), String> {
        let layout = self.layout;
        let binary = layout.binary(&rec.from_version);
        if !fs::metadata(&binary).is_ok_and(|m| m.is_file()) {
            return Err(format!(
                "cannot roll back: the previous version's binary {} is missing",
                binary.display()
            ));
        }
        if !rec.restarted
            && let Err(e) = self.systemd.systemctl(&["stop", UNIT_NAME])
        {
            tracing::warn!("cannot stop the new version before restoring the state: {e}");
        }
        fsx::replace_symlink(
            &layout.current(),
            &Path::new("versions").join(&rec.from_version),
        )
        .map_err(|e| format!("cannot point `current` back to {}: {e}", rec.from_version))?;
        let restored = restore_state(layout);
        if let Err(e) = &restored {
            tracing::error!(
                backup = %layout.backup_dir().display(),
                "cannot restore the state records ({e}); the backup is kept"
            );
        }
        let why = rec
            .rollback_reason
            .clone()
            .unwrap_or_else(|| "the new version did not confirm".into());
        self.report(rec, Outcome::RolledBack, Some(why))?;
        if !rec.restarted {
            let _ = self.systemd.systemctl(&["reset-failed", UNIT_NAME]);
            self.systemd
                .systemctl(&["restart", UNIT_NAME])
                .map_err(|e| {
                    format!("cannot restart the service into {}: {e}", rec.from_version)
                })?;
            rec.restarted = true;
            self.write(rec)?;
        }
        tracing::info!(version = rec.from_version.as_str(), "rolled back");
        self.clean_up(rec, true, restored.is_ok());
        Ok(())
    }

    fn finish_confirmed(&self, rec: &Record) -> Result<(), String> {
        self.report(rec, Outcome::Succeeded, None)?;
        prune_versions(self.layout);
        self.clean_up(rec, false, true);
        Ok(())
    }

    /// An update that stopped before the switch: nothing is running that was not before.
    fn fail_before_switch(&self, rec: &Record, why: &str) -> Result<Ended, String> {
        tracing::error!(reason = why, "the update stopped before the switch");
        self.report(rec, Outcome::Failed, Some(why.to_owned()))?;
        self.clean_up(rec, true, true);
        Ok(Ended::Failed)
    }

    /// Leaves the outcome for the agent to send, under the report id fixed when the update began.
    fn report(&self, rec: &Record, outcome: Outcome, why: Option<String>) -> Result<(), String> {
        PendingResult {
            report_id: rec.report_id.clone(),
            rollout_id: rec.rollout_id,
            version: rec.version.clone(),
            outcome,
            reason: why.map(|w| reason(&w)),
            occurred_at: rfc3339(self.clock.now()),
        }
        .write(&self.layout.state_dir)
        .map_err(|e| format!("cannot record the outcome: {e}"))
    }

    /// Removes what the update left: the staging directory and backup, the marker, and (when the new
    /// version is not the one running) its files. The record goes last, so an interrupted clean-up is
    /// repeated.
    fn clean_up(&self, rec: &Record, remove_new_version: bool, remove_backup: bool) {
        let layout = self.layout;
        let state = &layout.state_dir;
        let _ = fs::remove_dir_all(layout.staging(&rec.version));
        if remove_backup {
            let _ = fs::remove_dir_all(layout.backup_dir());
        }
        let _ = Marker::remove(state);
        if remove_new_version {
            let linked = [
                link_version(&layout.current()),
                link_version(&layout.previous()),
            ];
            if !linked.iter().any(|v| v.as_deref() == Some(&rec.version))
                && parse_version(&rec.version).is_some()
            {
                let _ = fs::remove_dir_all(layout.version_dir(&rec.version));
            }
        }
        let _ = Record::remove(state);
    }
}

/// Keeps the versions `current` and `previous` point to and removes the others (ADR 0018: two kept).
pub fn prune_versions(layout: &Layout) {
    let keep: Vec<String> = [layout.current(), layout.previous()]
        .iter()
        .filter_map(|link| link_version(link))
        .collect();
    let Ok(entries) = fs::read_dir(layout.versions_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        if is_dir && !keep.contains(&name) {
            if let Err(e) = fs::remove_dir_all(entry.path()) {
                tracing::warn!("cannot remove the old version {name}: {e}");
            } else {
                tracing::info!(version = name.as_str(), "removed an old version");
            }
        }
    }
}

/// The updater's own records, which are never part of a state backup.
fn is_update_file(name: &str) -> bool {
    [RECORD_FILE, MARKER_FILE, RESULT_FILE, LOCK_FILE].contains(&name) || name.starts_with('.')
}

/// Copies the state records (the regular files directly in the state directory) to `update/backup`,
/// so a rollback can put back exactly what the previous version last saw. The state is small JSON
/// records, so this is cheap and always done: a release cannot declare a state migration (the manifest
/// has no such field), and a backup nobody needs costs less than a restore nobody can make.
fn backup_state(layout: &Layout) -> io::Result<()> {
    let backup = layout.backup_dir();
    let _ = fs::remove_dir_all(&backup);
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&backup)?;
    for entry in fs::read_dir(&layout.state_dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_BACKUP_FILE || is_update_file(&name) {
            continue;
        }
        let bytes = fsx::read_regular(&entry.path(), MAX_BACKUP_FILE, fsx::Symlinks::Refuse)?;
        fsx::write_atomic(&backup.join(&name), &bytes, 0o600)?;
    }
    fsx::sync_dir(&backup)
}

/// Puts the backed-up records back. A record the new version created that was not in the backup is
/// left alone; the previous version reads state it does not know as missing.
fn restore_state(layout: &Layout) -> io::Result<()> {
    let backup = layout.backup_dir();
    let entries = match fs::read_dir(&backup) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_update_file(&name) {
            continue;
        }
        let bytes = fsx::read_regular(&entry.path(), MAX_BACKUP_FILE, fsx::Symlinks::Refuse)?;
        fsx::write_atomic(&layout.state_dir.join(&name), &bytes, 0o600)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
