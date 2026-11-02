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
use crate::install::{Systemctl, Systemd};
use crate::release::{self, ReleaseKey};
use crate::report::{Transport, rfc3339};
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

use fetch::{Fetch, FetchError, Opened, Resume};
use layout::{FileLock, LOCK_FILE, Layout, SUPERVISOR_UNIT, parse_version};
use record::{Marker, Outcome, PendingResult, Phase, Record, reason};
use stage::{Directive, StageError, Stager};
use supervise::{Intent, Supervisor, SystemClock, unix};

/// The API path for update outcomes.
pub const RESULTS_PATH: &str = "/api/v1/update-results";

/// How many times a download that fails for a transient reason is tried (once per heartbeat that still
/// carries the directive) before the update is reported `failed`.
const MAX_ATTEMPTS: u32 = 5;

/// How long an update record may sit unfinished before the agent gives up on it.
const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// How soon after starting a supervisor the agent may start another.
const RELAUNCH_AFTER: Duration = Duration::from_secs(30);

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
    busy: AtomicBool,
    memory: Mutex<Memory>,
}

/// The agent's side of remote updates. Cheap to clone; shared by the heartbeat loop and its worker.
#[derive(Clone)]
pub struct Updater {
    inner: Arc<Inner>,
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
                busy: AtomicBool::new(false),
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

    /// Runs the work of a directive on the calling thread (tests).
    #[cfg(test)]
    pub fn process_now(&self, directive: &Value) {
        if let Some(directive) = Directive::parse(directive) {
            self.inner.process(&directive);
        }
    }

    /// This process's first heartbeat the server acknowledged: if this is the version an update is
    /// waiting on, confirm it. This is the only thing the new version does for the update, and the
    /// supervisor alone decides what it means.
    pub fn on_first_ack(&self, wall: SystemTime) {
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
        let marker = Marker {
            rollout_id: rec.rollout_id,
            version: rec.version.clone(),
            pid: std::process::id(),
            confirmed_at: rfc3339(wall),
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
        let rec = match Record::read(&self.state_dir) {
            Ok(Some(rec)) => rec,
            Ok(None) => return,
            Err(e) => {
                if self.note_once("unreadable update record") {
                    tracing::error!("the update record is unreadable and will be removed: {e}");
                }
                let _ = Record::remove(&self.state_dir);
                return;
            }
        };
        let age = unix(SystemTime::now()).saturating_sub(rec.started_unix);
        if age > STALE_AFTER.as_secs() && rec.phase != Phase::Switched {
            self.give_up(layout, &rec);
            return;
        }
        match FileLock::try_lock(&self.state_dir.join(LOCK_FILE)) {
            Ok(Some(_free)) => {}
            Ok(None) => return, // a supervisor is working
            Err(e) => {
                tracing::warn!("cannot check for an update supervisor: {e}");
                return;
            }
        }
        let recent = self
            .memory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_launch
            .is_some_and(|at| at.elapsed() < RELAUNCH_AFTER);
        if recent || parse_version(&rec.from_version).is_none() {
            return;
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

    /// An update that never got anywhere for a day: reported, and cleared so later offers are not
    /// refused forever.
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
            Value(value) => {
                return Err(format!(
                    "unrecognised argument: {}",
                    cli::shown(&value.to_string_lossy())
                ));
            }
            Long(flag) => return Err(format!("unrecognised argument: {}", cli::long(flag))),
            Short(c) => return Err(format!("unrecognised argument: {}", cli::short(c))),
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
