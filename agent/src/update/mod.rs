//! Remote agent updates (FR-S.5, P1-AGENT-UPDATE, ADR 0018).
//!
//! The agent updates itself only through the signed release channel, and only forwards:
//!
//! - **[`Updater`]** runs inside the agent. A heartbeat's `agent_update` directive says which version
//!   to install and where to fetch it, nothing more. The updater downloads and verifies the release
//!   itself ([`stage`]: signature against the embedded keys, then the binary's SHA-256, never an older
//!   version), runs the staged binary's self-test, writes the update record, and starts the supervisor.
//!   Every refusal becomes a `failed` result with the reason.
//! - **[`supervise`]** is the supervisor, `fleet-agent update-supervise`, a transient systemd unit that
//!   runs the previous, known-good binary. It installs the version, swaps `current`, restarts the
//!   service, waits for the new version's confirmation, and rolls back without one.
//! - **`fleet-agent update-rollback`** is the same supervisor, started by the service's `OnFailure=`
//!   when the new version keeps crashing.
//! - **The results** (`succeeded`, `failed`, `rolled_back`) are written to the state directory by whoever
//!   reaches them and posted to `POST /api/v1/update-results` by the running agent, over and over, until
//!   the server accepts one ([`Updater::tick`]).
//! - **The watchdog** ([`Updater::start_watchdog`]) runs at startup and then on a timer of its own,
//!   independent of the heartbeat loop and its backoff: an update record with no supervisor holding the
//!   lock (it was killed, or the VM restarted) gets one, which finishes, rolls back, or fails it.
//!
//! The server never sends a command, a path, or a program. The directive's URLs are only fetched, with
//! no credential; the version becomes a path component only after it parses as a plain SemVer version;
//! and the commands that are run (`systemd-run`, `systemctl`, the staged binary's `self-test`) are
//! fixed by this code.
//!
//! The agent runs as root under a sandbox that lets it write only its state directory, so the parts
//! that change `/usr/lib/fleet-agent` and restart the service are in the supervisor, outside it.

pub mod fetch;
pub mod layout;
pub mod record;
pub mod stage;
pub mod supervise;

#[cfg(test)]
pub(crate) mod tests;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};

use crate::client::{ApiError, Client, SYSTEM_CA_BUNDLE};
use crate::config::Config;
use crate::fsx::Lock;
use crate::install::{Systemctl, Systemd};
use crate::release::{self, ReleaseKey};
use crate::report::{Transport, rfc3339};
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

use fetch::{Fetch, FetchError, Opened, Resume};
use layout::{LOCK_FILE, Layout, SUPERVISOR_UNIT, parse_version};
use record::{Marker, Outcome, PendingResult, Phase, Record, StateFile, reason};
use stage::{Directive, StageError, Stager};
use supervise::{Intent, STALE_AFTER, Supervisor, SystemClock, unix};

/// The API path for update outcomes.
pub const RESULTS_PATH: &str = "/api/v1/update-results";

/// How many times a download that fails for a transient reason is tried (once per heartbeat that still
/// carries the directive) before the update is reported `failed`.
const MAX_ATTEMPTS: u32 = 5;

/// How soon after starting a supervisor the agent may start another.
const RELAUNCH_AFTER: Duration = Duration::from_secs(30);

/// How often the watchdog looks for an update without a supervisor.
const WATCHDOG_EVERY: Duration = Duration::from_secs(10);

/// Default and allowed range of the confirmation deadline, in seconds (`update_confirm_seconds`).
pub const DEFAULT_CONFIRM_SECONDS: u64 = 300;
pub const MIN_CONFIRM_SECONDS: u64 = 10;
pub const MAX_CONFIRM_SECONDS: u64 = 3600;

/// Starts the supervisor outside the agent's sandbox. `systemd-run` in production.
pub trait Launcher: Send + Sync {
    /// Runs `binary update-supervise --config CONFIG` as the unit [`SUPERVISOR_UNIT`].
    fn start_supervisor(&self, binary: &Path, config: &Path) -> Result<(), String>;
}

struct SystemdRun(Systemctl);

impl Launcher for SystemdRun {
    fn start_supervisor(&self, binary: &Path, config: &Path) -> Result<(), String> {
        let (Some(binary), Some(config)) = (binary.to_str(), config.to_str()) else {
            return Err("a path is not valid UTF-8".into());
        };
        // `--collect`: a failed supervisor does not keep the unit name. The supervisor takes no other
        // input: what to do is in the update record, written by this agent.
        self.0
            .systemctl(&[
                "--unit",
                SUPERVISOR_UNIT,
                "--description=Fleet agent update supervisor",
                "--collect",
                "--quiet",
                "--",
                binary,
                "update-supervise",
                "--config",
                config,
            ])
            .map(drop)
    }
}

/// Stands in for a download client when the agent could not build one.
struct NoFetch(String);

impl Fetch for NoFetch {
    fn open(&self, _: &str, _: Option<Resume<'_>>) -> Result<Opened, FetchError> {
        Err(FetchError::Permanent(self.0.clone()))
    }
}

type SelfTest = dyn Fn(&Path, &semver::Version) -> Result<(), String> + Send + Sync;
type FreeBytes = dyn Fn(&Path) -> io::Result<u64> + Send + Sync;

/// What the updater remembers while the agent runs.
#[derive(Default)]
struct Memory {
    /// Failed downloads per (rollout, version).
    attempts: HashMap<(u64, String), u32>,
    /// Directives already answered, so a server that keeps sending one gets one result.
    reported: HashSet<(u64, String)>,
    last_launch: Option<Instant>,
    /// The last thing logged about posting results, so a repeating failure is logged once.
    last_post_problem: Option<String>,
    noted: HashSet<String>,
}

struct Inner {
    /// `None` when the agent does not run from `<lib>/versions/<its version>/`.
    layout: Option<Layout>,
    state_dir: PathBuf,
    config_path: PathBuf,
    confirm_seconds: u64,
    keys: Vec<ReleaseKey>,
    fetch: Box<dyn Fetch>,
    launcher: Box<dyn Launcher>,
    self_test: Box<SelfTest>,
    free_bytes: Box<FreeBytes>,
    running: semver::Version,
    /// The kernel's id of this boot.
    boot_id: Option<String>,
    busy: AtomicBool,
    /// The task poller holds a task (P3-A02): an update offer waits until it is reported.
    task_in_flight: AtomicBool,
    memory: Mutex<Memory>,
}

/// The agent's side of remote updates. Cheap to clone; shared by the heartbeat loop and its worker.
#[derive(Clone)]
pub struct Updater {
    inner: Arc<Inner>,
}

/// Held by the task poller from the poll that may claim a task until that task is reported
/// ([`Updater::task_slot`]). Dropping it lets update offers through again.
#[derive(Debug)]
pub struct TaskSlot<'a>(&'a AtomicBool);

impl Drop for TaskSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Updater {
    /// The updater of a running agent, configured from `config` (read from `config_path`).
    pub fn from_config(config: &Config, config_path: &Path) -> Self {
        let layout = std::env::current_exe()
            .ok()
            .and_then(|exe| Layout::detect(&exe, &config.state_dir));
        match &layout {
            Some(layout) => tracing::info!(
                lib_dir = %layout.lib_dir.display(),
                "remote updates are available: running from the side-by-side layout"
            ),
            None => tracing::info!(
                "this agent does not run from <lib>/versions/{AGENT_VERSION}/, so it cannot update itself"
            ),
        }
        let keys = release::embedded_keys().unwrap_or_else(|e| {
            tracing::error!("the release keys built into this binary are unusable: {e}");
            Vec::new()
        });
        let fetch: Box<dyn Fetch> = match Client::anonymous(
            &config.server_url,
            config.ca_file.as_deref(),
            Path::new(SYSTEM_CA_BUNDLE),
        ) {
            Ok(client) => Box::new(client),
            Err(e) => Box::new(NoFetch(format!("cannot build the download client: {e}"))),
        };
        let config_for_test = config_path.to_owned();
        Self::build(
            layout,
            config.state_dir.clone(),
            config_path.to_owned(),
            config.update_confirm_seconds,
            keys,
            fetch,
            Box::new(SystemdRun(Systemctl::systemd_run())),
            Box::new(move |binary, version| {
                stage::run_self_test(binary, &config_for_test, version)
            }),
            Box::new(layout::free_bytes),
            layout::boot_id(),
        )
    }

    /// An updater that cannot update: for a loop that runs without one (tests).
    #[cfg(test)]
    pub fn inert(state_dir: &Path) -> Self {
        Self::build(
            None,
            state_dir.to_owned(),
            PathBuf::from("/nonexistent/config.toml"),
            DEFAULT_CONFIRM_SECONDS,
            Vec::new(),
            Box::new(NoFetch("no download client".into())),
            Box::new(tests::NoLauncher),
            Box::new(|_, _| Err("no self-test".into())),
            Box::new(layout::free_bytes),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        layout: Option<Layout>,
        state_dir: PathBuf,
        config_path: PathBuf,
        confirm_seconds: u64,
        keys: Vec<ReleaseKey>,
        fetch: Box<dyn Fetch>,
        launcher: Box<dyn Launcher>,
        self_test: Box<SelfTest>,
        free_bytes: Box<FreeBytes>,
        boot_id: Option<String>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                layout,
                state_dir,
                config_path,
                confirm_seconds,
                keys,
                fetch,
                launcher,
                self_test,
                free_bytes,
                running: semver::Version::parse(AGENT_VERSION).expect("a SemVer package version"),
                boot_id,
                busy: AtomicBool::new(false),
                task_in_flight: AtomicBool::new(false),
                memory: Mutex::new(Memory::default()),
            }),
        }
    }

    /// A heartbeat carried an `agent_update` directive. The work (a download of some MiB) happens on a
    /// thread of its own, so a slow download never delays a heartbeat; a directive that arrives while
    /// one is being worked on, or while an update is in progress, is ignored.
    pub fn on_directive(&self, directive: &Value) {
        let Some(directive) = Directive::parse(directive) else {
            return;
        };
        if self.inner.busy.swap(true, Ordering::SeqCst) {
            return;
        }
        // A task in flight defers the update (P3-A02, L7): the offer comes again with every heartbeat.
        // `busy` is set before the check and the poller sets its flag before checking `busy`, both
        // sequentially consistent, so at least one of the two sees the other.
        if self.inner.task_in_flight.load(Ordering::SeqCst) {
            self.inner.busy.store(false, Ordering::SeqCst);
            if self
                .inner
                .note_once(&format!("deferred {}", directive.version))
            {
                tracing::info!(
                    offered_version = %directive.version,
                    "deferring the agent update: a task is in flight; it starts once the task is reported"
                );
            }
            return;
        }
        let inner = Arc::clone(&self.inner);
        let spawned = std::thread::Builder::new()
            .name("fleet-agent-update".into())
            .spawn(move || {
                let _guard = BusyGuard(&inner.busy);
                inner.process(&directive);
            });
        if let Err(e) = spawned {
            self.inner.busy.store(false, Ordering::SeqCst);
            tracing::error!("cannot start the update thread: {e}");
        }
    }

    /// The task poller is about to claim a task (P3-A02, L7): while the returned slot is held, update
    /// offers are deferred. `Err` says why no task may be claimed now: an update is being prepared, or
    /// one is in progress until it is confirmed or rolled back (its record exists).
    pub fn task_slot(&self) -> Result<TaskSlot<'_>, &'static str> {
        let flag = &self.inner.task_in_flight;
        flag.store(true, Ordering::SeqCst);
        let slot = TaskSlot(flag);
        if self.inner.busy.load(Ordering::SeqCst) {
            return Err("an agent update is being prepared");
        }
        match Record::read(&self.inner.state_dir) {
            Ok(None) => Ok(slot),
            Ok(Some(_)) => {
                Err("an agent update is in progress until it is confirmed or rolled back")
            }
            Err(_) => Err("the agent update record is unreadable"),
        }
    }

    /// Runs the work of a directive on the calling thread (tests).
    #[cfg(test)]
    pub fn process_now(&self, directive: &Value) {
        if let Some(directive) = Directive::parse(directive) {
            self.inner.process(&directive);
        }
    }

    /// This process's first heartbeat the server acknowledged, at `acked` (when the response arrived):
    /// if this is the version an update is waiting on, confirm it. This is the only thing the new version
    /// does for the update, and the supervisor alone decides what it means. A confirmation after the
    /// deadline, or after the VM restarted, is not written: ADR 0018 rolls those updates back.
    pub fn on_first_ack(&self, acked: SystemTime) {
        let state = &self.inner.state_dir;
        let rec = match Record::read(state) {
            Ok(Some(rec)) => rec,
            _ => return,
        };
        if rec.version != AGENT_VERSION
            || rec.from_version == AGENT_VERSION
            || !matches!(rec.phase, Phase::Switching | Phase::Switched)
        {
            return;
        }
        if rec.rebooted(self.inner.boot_id.as_deref()) {
            tracing::warn!(
                rollout_id = rec.rollout_id,
                "not confirming the update: the VM restarted before it was confirmed, so it will be rolled back"
            );
            return;
        }
        let acked_unix = unix(acked);
        if rec
            .deadline_unix
            .is_some_and(|deadline| acked_unix > deadline)
        {
            tracing::warn!(
                rollout_id = rec.rollout_id,
                "not confirming the update: the first acknowledged heartbeat came after the deadline, so it will be rolled back"
            );
            return;
        }
        let marker = Marker {
            rollout_id: rec.rollout_id,
            version: rec.version.clone(),
            pid: std::process::id(),
            confirmed_at: rfc3339(acked),
            confirmed_unix: acked_unix,
            boot_id: self.inner.boot_id.clone(),
        };
        match marker.write(state) {
            Ok(()) => tracing::info!(
                rollout_id = rec.rollout_id,
                "confirmed the update: the server acknowledged this version's heartbeat"
            ),
            Err(e) => tracing::error!(
                "cannot write the update confirmation ({e}); the update will be rolled back"
            ),
        }
    }

    /// Once per heartbeat round: posts the outcome waiting to be accepted, and makes sure an update in
    /// progress has a supervisor.
    pub fn tick(&self, transport: &dyn Transport) {
        self.inner.post_pending(transport);
        self.inner.watchdog();
    }

    /// Runs the watchdog now (the startup check: after a reboot, the update the VM restarted under gets
    /// a supervisor, which rolls it back) and then every [`WATCHDOG_EVERY`] on a thread of its own, so
    /// recovering an update never waits on the heartbeat loop or its backoff.
    pub fn start_watchdog(&self) {
        self.inner.watchdog();
        let inner = Arc::clone(&self.inner);
        let spawned = std::thread::Builder::new()
            .name("fleet-agent-update-watchdog".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(WATCHDOG_EVERY);
                    inner.watchdog();
                }
            });
        if let Err(e) = spawned {
            tracing::error!("cannot start the update watchdog: {e}");
        }
    }
}

/// For `fleet-agent install` and `uninstall`: the update lock of the state directory `state_dir`, so
/// neither can change `/usr/lib/fleet-agent` under an update. `Err` says why not: a supervisor is
/// running, or an update is recorded and unfinished. `Ok(None)` when there is no state directory.
pub fn hold_for_install(state_dir: &Path) -> Result<Option<Lock>, String> {
    if !state_dir.is_dir() {
        return Ok(None);
    }
    let lock = Lock::file(&state_dir.join(LOCK_FILE)).map_err(|e| {
        format!(
            "cannot check for an agent update in {}: {e}",
            state_dir.display()
        )
    })?;
    let Some(lock) = lock else {
        return Err("an agent update is in progress on this VM (its supervisor is running)".into());
    };
    match Record::read(state_dir) {
        Ok(None) => Ok(Some(lock)),
        Ok(Some(rec)) => Err(format!(
            "an agent update to {} is in progress on this VM (recorded in {})",
            crate::logging::sanitize(&rec.version, 64),
            state_dir.join(layout::RECORD_FILE).display()
        )),
        Err(e) => Err(format!(
            "the agent update record in {} is unreadable ({e})",
            state_dir.display()
        )),
    }
}

impl Inner {
    fn note_once(&self, note: &str) -> bool {
        let mut memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
        memory.noted.insert(note.to_owned())
    }

    fn process(&self, directive: &Directive) {
        let key = (directive.rollout_id, directive.version.to_string());
        let in_progress = matches!(Record::read(&self.state_dir), Ok(Some(_)))
            || matches!(PendingResult::read(&self.state_dir), Ok(Some(_)));
        let answered = self
            .memory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reported
            .contains(&key);
        if in_progress || answered {
            if self.note_once(&format!("ignored {} {}", key.0, key.1)) {
                tracing::info!(
                    offered_version = key.1.as_str(),
                    "ignoring the update offer: an update is in progress or already answered"
                );
            }
            return;
        }
        match self.attempt(directive) {
            Ok(()) => {}
            Err(StageError::Failed(why)) => self.fail(directive, &why),
            Err(StageError::Retry(why)) => {
                let attempts = {
                    let mut memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
                    let n = memory.attempts.entry(key).or_insert(0);
                    *n += 1;
                    *n
                };
                if attempts >= MAX_ATTEMPTS {
                    self.fail(directive, &format!("{why} (after {attempts} attempts)"));
                } else {
                    tracing::warn!(
                        attempt = attempts,
                        "the update download did not complete ({why}); it will continue with the next heartbeat"
                    );
                }
            }
        }
    }

    /// Stages the release and hands it to the supervisor.
    fn attempt(&self, directive: &Directive) -> Result<(), StageError> {
        let Some(layout) = &self.layout else {
            return Err(StageError::Failed(format!(
                "this agent does not run from <lib>/versions/{AGENT_VERSION}/, so it cannot update itself; run `fleet-agent install` with the new binary instead"
            )));
        };
        tracing::info!(
            rollout_id = directive.rollout_id,
            offered_version = %directive.version,
            "the server offered an update; downloading and verifying it"
        );
        Stager {
            layout,
            keys: &self.keys,
            fetch: &*self.fetch,
            running: &self.running,
            free_bytes: &*self.free_bytes,
            self_test: &*self.self_test,
        }
        .stage(directive)?;

        let report_id = crate::report::new_report_id()
            .map_err(|e| StageError::Failed(format!("cannot make a report id: {e}")))?;
        let _ = Marker::remove(&self.state_dir);
        let record = Record {
            rollout_id: directive.rollout_id,
            version: directive.version.to_string(),
            from_version: self.running.to_string(),
            phase: Phase::Staged,
            started_unix: unix(SystemTime::now()),
            report_id,
            confirm_seconds: self.confirm_seconds,
            deadline_unix: None,
            restarted: false,
            rollback_reason: None,
            boot_id: self.boot_id.clone(),
            previous_before: None,
        };
        record
            .write(&self.state_dir)
            .map_err(|e| StageError::Failed(format!("cannot write the update record: {e}")))?;
        tracing::info!(version = %directive.version, "verified; starting the update supervisor");
        if let Err(why) = self.launch(layout, &record.from_version) {
            let _ = Record::remove(&self.state_dir);
            let _ = std::fs::remove_dir_all(layout.staging(&record.version));
            return Err(StageError::Failed(format!(
                "cannot start the update supervisor: {why}"
            )));
        }
        // Handed over: whatever the supervisor decides, this process does not act on the offer again.
        self.memory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reported
            .insert((directive.rollout_id, directive.version.to_string()));
        Ok(())
    }

    fn launch(&self, layout: &Layout, from_version: &str) -> Result<(), String> {
        let binary = layout.binary(from_version);
        if !std::fs::metadata(&binary).is_ok_and(|m| m.is_file()) {
            return Err(format!("{} is missing", binary.display()));
        }
        self.memory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_launch = Some(Instant::now());
        self.launcher.start_supervisor(&binary, &self.config_path)
    }

    /// Records a `failed` result for the posting loop. Nothing was installed.
    fn fail(&self, directive: &Directive, why: &str) {
        tracing::error!(
            rollout_id = directive.rollout_id,
            offered_version = %directive.version,
            "the update was refused: {why}"
        );
        let Ok(report_id) = crate::report::new_report_id() else {
            return;
        };
        let result = PendingResult {
            report_id,
            rollout_id: directive.rollout_id,
            version: directive.version.to_string(),
            outcome: Outcome::Failed,
            reason: Some(reason(why)),
            occurred_at: rfc3339(SystemTime::now()),
        };
        match result.write(&self.state_dir) {
            Ok(()) => {
                self.memory
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .reported
                    .insert((directive.rollout_id, directive.version.to_string()));
            }
            Err(e) => tracing::error!("cannot record the update result: {e}"),
        }
    }

    /// Posts the outcome waiting in the state directory. Kept, and sent again with the same
    /// `report_id`, until the server accepts it; only a response that says the result itself is wrong
    /// (a `4xx` that retrying cannot change) drops it.
    fn post_pending(&self, transport: &dyn Transport) {
        let pending = match PendingResult::read(&self.state_dir) {
            Ok(Some(pending)) => pending,
            Ok(None) => return,
            Err(e) => {
                tracing::error!("dropping an unreadable update result: {e}");
                let _ = PendingResult::remove(&self.state_dir);
                return;
            }
        };
        let mut body = json!({
            "schema_version": AGENT_SCHEMA_VERSION,
            "agent_version": AGENT_VERSION,
            "report_id": pending.report_id,
            "rollout_id": pending.rollout_id,
            "version": pending.version,
            "outcome": pending.outcome.as_str(),
            "occurred_at": pending.occurred_at,
        });
        if let Some(why) = &pending.reason {
            body["reason"] = json!(why);
        }
        let outcome = pending.outcome.as_str();
        match transport.post(RESULTS_PATH, &body) {
            Ok(response) => {
                tracing::info!(
                    rollout_id = pending.rollout_id,
                    outcome,
                    duplicate = response.body["duplicate"].as_bool().unwrap_or(false),
                    "the server accepted the update result"
                );
                self.memory
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last_post_problem = None;
                if let Err(e) = PendingResult::remove(&self.state_dir) {
                    tracing::error!("cannot remove the posted update result: {e}");
                }
            }
            Err(error @ ApiError::Rejected { .. }) => {
                tracing::error!(
                    rollout_id = pending.rollout_id,
                    outcome,
                    status = error.status(),
                    request_id = error.request_id().unwrap_or(""),
                    "the server rejected the update result and will not accept it; dropping it"
                );
                let _ = PendingResult::remove(&self.state_dir);
            }
            Err(error) => {
                let problem = format!("{error:?}");
                let mut memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
                if memory.last_post_problem.as_deref() != Some(&problem) {
                    tracing::warn!(
                        rollout_id = pending.rollout_id,
                        outcome,
                        status = error.status(),
                        "cannot post the update result yet; it will be sent again"
                    );
                    memory.last_post_problem = Some(problem);
                }
            }
        }
    }

    /// An update in the record needs a supervisor. If none holds the lock (it was killed, or the VM
    /// restarted), start one from the version being replaced; it carries on from the recorded phase.
    fn watchdog(&self) {
        let Some(layout) = &self.layout else { return };
        // While this process's worker is staging and handing over, the record it just wrote has no
        // supervisor yet; that is not a dead supervisor, and starting one here would race the handover.
        if self.busy.load(Ordering::SeqCst) {
            return;
        }
        match Record::read(&self.state_dir) {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(e) => {
                if self.note_once("unreadable update record") {
                    tracing::error!("the update record is unreadable and will be removed: {e}");
                }
                let _ = Record::remove(&self.state_dir);
                return;
            }
        };
        let lock = match Lock::file(&self.state_dir.join(LOCK_FILE)) {
            Ok(Some(lock)) => lock,
            Ok(None) => return, // a supervisor is working
            Err(e) => {
                tracing::warn!("cannot check for an update supervisor: {e}");
                return;
            }
        };
        // Read again under the lock: a supervisor may have finished between the two reads.
        let rec = match Record::read(&self.state_dir) {
            Ok(Some(rec)) => rec,
            _ => return,
        };
        // Abandoned only when it provably never switched: nothing is selected that was not before.
        // Anything else, however old, goes to a supervisor, which rolls back an unconfirmed version.
        let age = unix(SystemTime::now()).saturating_sub(rec.started_unix);
        let pre_switch = !rec.past_switch()
            && layout::link_version(&layout.current()).as_deref()
                == Some(rec.from_version.as_str());
        if age > STALE_AFTER.as_secs() && pre_switch {
            self.give_up(layout, &rec);
            return;
        }
        drop(lock);
        {
            let mut memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
            if memory
                .last_launch
                .is_some_and(|at| at.elapsed() < RELAUNCH_AFTER)
                || parse_version(&rec.from_version).is_none()
            {
                return;
            }
            // Claimed here, under the same lock as the check, so the timer and a heartbeat round
            // never both start one.
            memory.last_launch = Some(Instant::now());
        }
        tracing::warn!(
            phase = ?rec.phase,
            rollout_id = rec.rollout_id,
            "an update is unfinished and no supervisor is running; starting one to carry it on"
        );
        if let Err(why) = self.launch(layout, &rec.from_version) {
            tracing::error!("cannot start the update supervisor: {why}");
        }
    }

    /// An update that never got to the switch in a day: reported, and cleared so later offers are not
    /// refused forever. Only for an update that provably did not switch (checked under the lock).
    fn give_up(&self, layout: &Layout, rec: &Record) {
        tracing::error!(
            rollout_id = rec.rollout_id,
            "giving up on an update that did not finish"
        );
        let result = PendingResult {
            report_id: rec.report_id.clone(),
            rollout_id: rec.rollout_id,
            version: rec.version.clone(),
            outcome: Outcome::Failed,
            reason: Some(reason("the update did not finish within 24 hours")),
            occurred_at: rfc3339(SystemTime::now()),
        };
        if result.write(&self.state_dir).is_ok() {
            if parse_version(&rec.version).is_some() {
                let _ = std::fs::remove_dir_all(layout.staging(&rec.version));
            }
            let _ = Record::remove(&self.state_dir);
        }
    }
}

// --- The commands ------------------------------------------------------------------------------------

const USAGE: &str = "\
Usage: fleet-agent self-test [--config PATH]
       fleet-agent update-supervise [--config PATH]        (run by the agent; see below)
       fleet-agent update-rollback --reason crash-loop [--config PATH]   (run by systemd; see below)

self-test checks, without contacting the server, that this binary can start with this host's
configuration: it reads the config and the trusted certificates and the state directory. The agent runs
it on a downloaded release before installing it. Prints `self-test OK: fleet-agent VERSION ...` and
exits 0, or says what is wrong and exits 1.

update-supervise installs the release the agent staged, switches to it, and rolls back if it does not
confirm (P1-AGENT-UPDATE). The agent starts it with systemd-run. update-rollback is the same supervisor,
started by the service's OnFailure= hook: it rolls back an update the new version did not confirm.
Neither takes anything from the server; both read the update record in the state directory.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    SelfTest(PathBuf),
    Supervise(PathBuf, Intent),
    Help,
}

fn parse_args(args: Vec<OsString>) -> Result<Command, String> {
    use crate::cli;
    use lexopt::prelude::*;
    let mut args = args.into_iter();
    let name = args
        .next()
        .and_then(|a| a.into_string().ok())
        .unwrap_or_default();
    let mut parser = lexopt::Parser::from_args(args);
    let mut config: Option<PathBuf> = None;
    let mut why: Option<String> = None;
    while let Some(arg) = parser.next().map_err(cli::error_text)? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Short('c') | Long("config") => {
                let value = parser.value().map_err(cli::error_text)?;
                if value.is_empty() || config.replace(PathBuf::from(value)).is_some() {
                    return Err("--config needs one path".into());
                }
            }
            Long("reason") if name == "update-rollback" => {
                let value = parser.value().map_err(cli::error_text)?;
                why = Some(value.to_string_lossy().into_owned());
            }
            other => return Err(format!("unrecognised argument: {}", cli::arg(other))),
        }
    }
    let config = config.unwrap_or_else(|| PathBuf::from(crate::config::DEFAULT_CONFIG_PATH));
    match name.as_str() {
        "self-test" => Ok(Command::SelfTest(config)),
        "update-supervise" => Ok(Command::Supervise(config, Intent::Resume)),
        "update-rollback" => match why.as_deref() {
            Some("crash-loop") => Ok(Command::Supervise(
                config,
                Intent::Rollback("the new version kept failing and systemd stopped restarting it"),
            )),
            _ => Err("--reason must be crash-loop".into()),
        },
        _ => Err("unknown command".into()),
    }
}

/// `fleet-agent self-test`, `update-supervise`, and `update-rollback`. `args[0]` is the command.
pub fn main(args: Vec<OsString>) -> ExitCode {
    match parse_args(args) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::SelfTest(config)) => self_test(&config),
        Ok(Command::Supervise(config, intent)) => supervise_main(&config, intent),
        Err(message) => {
            eprintln!("fleet-agent: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// `self-test`: this binary can run on this host's configuration. Contacts nothing, changes nothing.
fn self_test(config_path: &Path) -> ExitCode {
    let fail = |what: String| {
        eprintln!("fleet-agent: self-test failed: {what}");
        ExitCode::FAILURE
    };
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(e) => return fail(e.to_string()),
    };
    if let Err(e) = Client::new(&config) {
        return fail(e.to_string());
    }
    match std::fs::read_dir(&config.state_dir) {
        Ok(_) => {}
        Err(e) => {
            return fail(format!(
                "cannot read the state directory {}: {e}",
                config.state_dir.display()
            ));
        }
    }
    println!(
        "{} {AGENT_VERSION} (agent schema {AGENT_SCHEMA_VERSION})",
        stage::SELF_TEST_OK
    );
    ExitCode::SUCCESS
}

fn supervise_main(config_path: &Path, intent: Intent) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("fleet-agent: {e}");
            return ExitCode::FAILURE;
        }
    };
    crate::logging::init(config.log_level);
    let exe = std::env::current_exe().ok();
    let Some(layout) = exe
        .as_deref()
        .and_then(|exe| Layout::detect(exe, &config.state_dir))
    else {
        tracing::error!(
            "the supervisor must run from <lib>/versions/{AGENT_VERSION}/fleet-agent, the version being replaced"
        );
        return ExitCode::FAILURE;
    };
    let keys = release::embedded_keys().unwrap_or_default();
    let systemd = Systemctl::default();
    let running = semver::Version::parse(AGENT_VERSION).expect("a SemVer package version");
    let supervisor = Supervisor {
        layout: &layout,
        keys: &keys,
        systemd: &systemd,
        clock: &SystemClock,
        running: &running,
        poll: Duration::from_secs(1),
        boot_id: layout::boot_id(),
        swap_current: crate::fsx::replace_symlink,
    };
    match supervisor.run(intent) {
        Ok(ended) => {
            tracing::info!(?ended, "update supervisor finished");
            ExitCode::SUCCESS
        }
        Err(why) => {
            tracing::error!("update supervisor stopped: {why}");
            ExitCode::FAILURE
        }
    }
}
