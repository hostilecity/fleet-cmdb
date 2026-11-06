//! Tests of the updater inside the agent, and the fixtures the supervisor's tests share: a fake
//! machine (a lib directory, a state directory, a clock, a `systemctl`) and a signed release.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::fetch::tests::FakeFetch;
use super::layout::{MARKER_FILE, RECORD_FILE, RESULT_FILE, link_version};
use super::stage::tests::{BASE, TestKey, binary, directive, manifest, publish};
use super::stage::{BINARY_STAGED, MANIFEST_NAME, SIGNATURE_NAME};
use super::supervise::Clock;
use super::*;
use crate::client::ApiResponse;
use crate::collect::contract::assert_conforms;
use crate::install::UNIT_NAME;
use crate::release::KeyRole;
use crate::report::tests::{FakeTransport, ok};
use crate::test_support::{TempDir, dir_with_mode};

pub struct NoLauncher;

impl Launcher for NoLauncher {
    fn start_supervisor(&self, _: &Path, _: &Path) -> Result<(), String> {
        Err("no supervisor in this test".into())
    }
}

/// The version of the agent under test, which is the version being replaced.
pub fn old() -> &'static str {
    AGENT_VERSION
}

/// A version newer than any this agent will ever be.
pub const NEW: &str = "99.0.0";

/// The boot id of the fake machine until a test restarts it.
pub const BOOT: &str = "boot-1";

// --- The fake machine ----------------------------------------------------------------------------

/// Seconds since the Unix epoch, advanced by `sleep` instead of waiting, and something to do once that
/// time is reached (another process finishing, say).
pub struct FakeClock(pub Cell<u64>, pub RefCell<Option<Alarm>>);

/// Something to do at a time: `(unix seconds, what)`.
pub type Alarm = (u64, Box<dyn FnOnce()>);

impl FakeClock {
    pub fn at(&self, unix: u64, then: impl FnOnce() + 'static) {
        *self.1.borrow_mut() = Some((unix, Box::new(then)));
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.0.get())
    }
    fn sleep(&self, duration: Duration) {
        self.0.set(self.0.get() + duration.as_secs().max(1));
        let due = matches!(&*self.1.borrow(), Some((at, _)) if *at <= self.0.get());
        if due && let Some((_, then)) = self.1.borrow_mut().take() {
            then();
        }
    }
}

/// What a version does when systemd starts it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Agent {
    /// Heartbeats are acknowledged: it writes the marker.
    Confirms,
    /// Runs, but never gets a heartbeat acknowledged (cannot authenticate).
    Silent,
    /// Exits at start, or crash-loops, until systemd gives up.
    Fails,
}

/// A `systemctl` that starts whichever version `current` points to, as that version would behave.
pub struct FakeSystemd {
    pub calls: RefCell<Vec<String>>,
    pub lib_dir: PathBuf,
    pub state_dir: PathBuf,
    pub behaviour: RefCell<HashMap<String, Agent>>,
    pub state: RefCell<String>,
    pub fail_restart: Cell<bool>,
    /// The lock of another supervisor, held until `systemctl kill` kills it.
    pub other_supervisor: RefCell<Option<crate::fsx::Lock>>,
    /// The kernel's boot id; a test changes it to restart the VM.
    pub boot: RefCell<Option<String>>,
    /// The version the service is running, if it is running.
    pub running: RefCell<Option<String>>,
}

impl FakeSystemd {
    pub fn restarts(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| *c == "restart")
            .count()
    }
}

impl Systemd for FakeSystemd {
    fn unavailable(&self) -> Option<String> {
        None
    }

    fn systemctl(&self, args: &[&str]) -> Result<String, String> {
        // A running new version keeps saving its state (an inventory report in flight) until stopped.
        if self.running.borrow().as_deref().is_some_and(|v| v != old()) {
            fs::write(self.state_dir.join("inventory.json"), r#"{"v":"new"}"#).unwrap();
        }
        match args {
            ["stop", unit] => {
                assert_eq!(*unit, UNIT_NAME);
                self.calls.borrow_mut().push("stop".into());
                *self.running.borrow_mut() = None;
                *self.state.borrow_mut() = "inactive".into();
                Ok(String::new())
            }
            ["restart", unit] => {
                assert_eq!(*unit, UNIT_NAME);
                self.calls.borrow_mut().push("restart".into());
                if self.fail_restart.get() {
                    return Err("Job for fleet-agent.service failed".into());
                }
                let version = link_version(&self.lib_dir.join("current")).unwrap();
                let behaviour = self
                    .behaviour
                    .borrow()
                    .get(&version)
                    .copied()
                    .unwrap_or(Agent::Confirms);
                // A newer version rewrites the state it keeps, as a migration would.
                if version != old() {
                    fs::write(self.state_dir.join("inventory.json"), r#"{"v":"new"}"#).unwrap();
                }
                *self.state.borrow_mut() = if behaviour == Agent::Fails {
                    "failed".into()
                } else {
                    "active".into()
                };
                *self.running.borrow_mut() = (behaviour != Agent::Fails).then(|| version.clone());
                if behaviour == Agent::Confirms
                    && let Ok(Some(rec)) = Record::read(&self.state_dir)
                    && rec.version == version
                {
                    Marker {
                        rollout_id: rec.rollout_id,
                        version,
                        pid: 4242,
                        confirmed_at: "2026-01-01T12:00:00Z".into(),
                        confirmed_unix: 0,
                        boot_id: self.boot.borrow().clone(),
                    }
                    .write(&self.state_dir)
                    .unwrap();
                }
                Ok(String::new())
            }
            ["reset-failed", _] => {
                self.calls.borrow_mut().push("reset-failed".into());
                Ok(String::new())
            }
            ["is-active", _] => {
                let state = self.state.borrow().clone();
                if state == "active" {
                    Ok(state)
                } else {
                    Err(state)
                }
            }
            ["kill", "--signal=SIGKILL", unit] => {
                assert_eq!(*unit, "fleet-agent-update.service");
                self.calls.borrow_mut().push("kill-supervisor".into());
                self.other_supervisor.borrow_mut().take();
                Ok(String::new())
            }
            other => panic!("unexpected systemctl call: {other:?}"),
        }
    }
}

/// A machine with version [`old`] installed and running, in a temporary directory.
pub struct World {
    pub _dir: TempDir,
    pub layout: Layout,
    pub key: TestKey,
    pub keys: Vec<ReleaseKey>,
    pub clock: FakeClock,
    pub systemd: FakeSystemd,
    pub running: semver::Version,
    /// How the supervisor swaps `current`.
    pub swap_current: Cell<fn(&Path, &Path) -> io::Result<()>>,
}

pub const OLD_BINARY: &[u8] = b"#!/bin/sh\n# the old agent\n";

impl World {
    pub fn new() -> Self {
        let dir = TempDir::new();
        let layout = Layout::new(dir.path("lib"), dir.path("state"));
        fs::create_dir_all(layout.version_dir(old())).unwrap();
        fs::write(layout.binary(old()), OLD_BINARY).unwrap();
        fs::set_permissions(layout.binary(old()), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(Path::new("versions").join(old()), layout.current()).unwrap();
        dir_with_mode(&layout.state_dir, 0o700);
        fs::write(layout.state_dir.join("inventory.json"), r#"{"v":"old"}"#).unwrap();
        fs::write(layout.state_dir.join("heartbeat.json"), r#"{"pid":1}"#).unwrap();
        let key = TestKey::generate();
        let keys = vec![key.release_key(KeyRole::Current)];
        let systemd = FakeSystemd {
            calls: RefCell::default(),
            lib_dir: layout.lib_dir.clone(),
            state_dir: layout.state_dir.clone(),
            behaviour: RefCell::default(),
            state: RefCell::new("active".into()),
            fail_restart: Cell::new(false),
            other_supervisor: RefCell::default(),
            boot: RefCell::new(Some(BOOT.into())),
            running: RefCell::new(Some(old().into())),
        };
        Self {
            _dir: dir,
            layout,
            key,
            keys,
            clock: FakeClock(Cell::new(1_767_268_800), RefCell::default()),
            systemd,
            running: semver::Version::parse(old()).unwrap(),
            swap_current: Cell::new(crate::fsx::replace_symlink),
        }
    }

    pub fn state(&self) -> &Path {
        &self.layout.state_dir
    }

    pub fn supervisor(&self) -> supervise::Supervisor<'_> {
        supervise::Supervisor {
            layout: &self.layout,
            keys: &self.keys,
            systemd: &self.systemd,
            clock: &self.clock,
            running: &self.running,
            poll: Duration::from_secs(1),
            boot_id: self.systemd.boot.borrow().clone(),
            swap_current: self.swap_current.get(),
        }
    }

    /// Restarts the VM: a new boot id, and no supervisor or lock survives.
    pub fn reboot(&self) {
        *self.systemd.boot.borrow_mut() = Some("boot-2".into());
    }

    pub fn run(&self, intent: Intent) -> Result<supervise::Ended, String> {
        self.supervisor().run(intent)
    }

    /// What systemd would start now.
    pub fn current(&self) -> Option<String> {
        link_version(&self.layout.current())
    }

    pub fn previous(&self) -> Option<String> {
        link_version(&self.layout.previous())
    }

    pub fn behaves(&self, version: &str, agent: Agent) {
        self.systemd
            .behaviour
            .borrow_mut()
            .insert(version.to_owned(), agent);
    }

    /// Stages a signed release of `body` as the agent would have, and writes the `Staged` record.
    pub fn stage_release(&self, version: &str, body: &[u8], rollout_id: u64) -> Record {
        let dir = self.layout.staging(version);
        fs::create_dir_all(&dir).unwrap();
        let manifest = manifest(body, version);
        fs::write(dir.join(MANIFEST_NAME), &manifest).unwrap();
        fs::write(dir.join(SIGNATURE_NAME), self.key.sign(&manifest)).unwrap();
        fs::write(dir.join(BINARY_STAGED), body).unwrap();
        let record = Record {
            rollout_id,
            version: version.to_owned(),
            from_version: old().to_owned(),
            phase: Phase::Staged,
            started_unix: self.clock.0.get(),
            report_id: "00000000-0000-4000-8000-0000000000aa".into(),
            confirm_seconds: 300,
            deadline_unix: None,
            restarted: false,
            rollback_reason: None,
            boot_id: Some(BOOT.into()),
            previous_before: None,
        };
        record.write(self.state()).unwrap();
        record
    }

    pub fn pending(&self) -> Option<PendingResult> {
        PendingResult::read(self.state()).unwrap()
    }

    pub fn inventory(&self) -> String {
        fs::read_to_string(self.state().join("inventory.json")).unwrap()
    }
}

// --- The updater inside the agent -----------------------------------------------------------------

/// Records the supervisors it was asked to start.
#[derive(Clone, Default)]
pub struct RecordingLauncher {
    pub started: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    pub fail: Arc<AtomicBool>,
}

impl Launcher for RecordingLauncher {
    fn start_supervisor(&self, binary: &Path, config: &Path) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("Failed to connect to bus".into());
        }
        self.started
            .lock()
            .unwrap()
            .push((binary.to_owned(), config.to_owned()));
        Ok(())
    }
}

/// An updater on a [`World`] with a fake download server.
struct Rig {
    world: World,
    fetch: Arc<FakeFetch>,
    launcher: RecordingLauncher,
    updater: Updater,
    self_test: Arc<Mutex<Result<(), String>>>,
}

struct SharedFetch(Arc<FakeFetch>);

impl Fetch for SharedFetch {
    fn open(&self, url: &str, resume: Option<Resume<'_>>) -> Result<Opened, FetchError> {
        self.0.open(url, resume)
    }
}

impl Rig {
    fn new() -> Self {
        Self::with_layout(true)
    }

    fn with_layout(installed: bool) -> Self {
        let world = World::new();
        let fetch = Arc::new(FakeFetch::default());
        let launcher = RecordingLauncher::default();
        let self_test: Arc<Mutex<Result<(), String>>> = Arc::new(Mutex::new(Ok(())));
        let test = Arc::clone(&self_test);
        let updater = Updater::build(
            installed.then(|| world.layout.clone()),
            world.layout.state_dir.clone(),
            PathBuf::from("/etc/fleet-agent/config.toml"),
            300,
            world.keys.clone(),
            Box::new(SharedFetch(Arc::clone(&fetch))),
            Box::new(launcher.clone()),
            Box::new(move |_, _| test.lock().unwrap().clone()),
            Box::new(|_| Ok(10 << 30)),
            Some(BOOT.into()),
        );
        Self {
            world,
            fetch,
            launcher,
            updater,
            self_test,
        }
    }

    fn offer(&self, version: &str, rollout_id: u64) -> Value {
        let d = publish(
            &self.fetch,
            &self.world.key,
            version,
            &binary(20_000),
            rollout_id,
        );
        directive_json(&d)
    }
}

fn directive_json(d: &Directive) -> Value {
    json!({
        "rollout_id": d.rollout_id,
        "version": d.version.to_string(),
        "manifest_url": d.manifest_url,
        "signature_url": d.signature_url,
        "binary_url": d.binary_url,
    })
}

fn accepted(body: &Value) -> Result<ApiResponse, ApiError> {
    ok(json!({"report_id": body["report_id"], "duplicate": false}))
}

#[test]
fn a_good_directive_is_verified_staged_and_handed_to_the_supervisor() {
    let rig = Rig::new();
    rig.updater.process_now(&rig.offer(NEW, 5));

    let record = Record::read(rig.world.state()).unwrap().unwrap();
    assert_eq!((record.rollout_id, record.version.as_str()), (5, NEW));
    assert_eq!(record.from_version, old());
    assert_eq!(record.phase, Phase::Staged);
    assert_eq!(record.confirm_seconds, 300);
    assert!(rig.world.pending().is_none(), "nothing is reported yet");
    // The supervisor is the version being replaced, with the agent's own config path.
    let started = rig.launcher.started.lock().unwrap().clone();
    assert_eq!(
        started,
        [(
            rig.world.layout.binary(old()),
            PathBuf::from("/etc/fleet-agent/config.toml")
        )]
    );
    // Nothing is installed by the agent itself: it cannot (its sandbox), and the supervisor does.
    assert_eq!(rig.world.current().as_deref(), Some(old()));
    assert!(!rig.world.layout.version_dir(NEW).exists());
}

#[test]
fn an_offer_handed_to_the_supervisor_is_not_acted_on_again_by_this_process() {
    // The supervisor failed the update before the switch and its result was accepted (record and
    // result gone); the server still sends the directive until it has processed the result.
    let rig = Rig::new();
    let offer = rig.offer(NEW, 5);
    rig.updater.process_now(&offer);
    Record::remove(rig.world.state()).unwrap();
    rig.updater.process_now(&offer);
    assert_eq!(rig.launcher.started.lock().unwrap().len(), 1);
    assert!(Record::read(rig.world.state()).unwrap().is_none());
}

#[test]
fn every_refusal_is_reported_failed_and_changes_nothing() {
    let rig = Rig::new();
    let key = &rig.world.key;
    let other = TestKey::generate();

    // Tampered binary, unsigned manifest, unknown key, older version.
    let tampered = rig.offer("98.0.0", 1);
    let mut evil = binary(20_000);
    evil[5] ^= 1;
    rig.fetch
        .put(tampered["binary_url"].as_str().unwrap(), &evil);
    let unsigned = {
        let d = publish(&rig.fetch, key, "97.0.0", &binary(20_000), 2);
        rig.fetch.put(&d.signature_url, b"");
        directive_json(&d)
    };
    let unknown = directive_json(&publish(&rig.fetch, &other, "96.0.0", &binary(20_000), 3));
    let older = directive_json(&publish(&rig.fetch, key, "0.0.1", &binary(20_000), 4));

    for (directive, expect) in [
        (tampered, "SHA-256"),
        (unsigned, "not a minisign signature"),
        (unknown, "does not trust"),
        (older, "not newer"),
    ] {
        rig.updater.process_now(&directive);
        let result = rig.world.pending().expect("a refusal is reported");
        assert_eq!(result.outcome, Outcome::Failed);
        assert!(result.reason.unwrap().contains(expect), "{expect}");
        assert_eq!(result.rollout_id, directive["rollout_id"]);
        PendingResult::remove(rig.world.state()).unwrap();
        // The running version is unchanged and no update is in progress.
        assert_eq!(rig.world.current().as_deref(), Some(old()));
        assert!(Record::read(rig.world.state()).unwrap().is_none());
    }
    assert!(rig.launcher.started.lock().unwrap().is_empty());
    assert!(!rig.world.layout.versions_dir().join("98.0.0").exists());
}

#[test]
fn a_failed_self_test_or_supervisor_start_is_reported_failed() {
    let rig = Rig::new();
    *rig.self_test.lock().unwrap() = Err("the config is not valid".into());
    rig.updater.process_now(&rig.offer(NEW, 5));
    let result = rig.world.pending().unwrap();
    assert!(result.reason.unwrap().contains("self-test"));
    PendingResult::remove(rig.world.state()).unwrap();

    *rig.self_test.lock().unwrap() = Ok(());
    rig.launcher.fail.store(true, Ordering::SeqCst);
    rig.updater.process_now(&rig.offer("99.1.0", 6));
    let result = rig.world.pending().unwrap();
    assert!(
        result
            .reason
            .unwrap()
            .contains("cannot start the update supervisor")
    );
    assert!(Record::read(rig.world.state()).unwrap().is_none());
    assert!(!rig.world.layout.staging("99.1.0").exists());
}

#[test]
fn an_agent_outside_the_side_by_side_layout_reports_why_it_cannot_update() {
    let rig = Rig::with_layout(false);
    rig.updater.process_now(&rig.offer(NEW, 5));
    let result = rig.world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::Failed);
    assert!(result.reason.unwrap().contains("fleet-agent install"));
}

#[test]
fn one_update_at_a_time_and_one_answer_per_offer() {
    let rig = Rig::new();
    let first = rig.offer(NEW, 5);
    rig.updater.process_now(&first);
    assert_eq!(rig.launcher.started.lock().unwrap().len(), 1);
    // While the update is in progress, another offer is ignored (even a different rollout).
    rig.updater.process_now(&rig.offer("99.1.0", 6));
    rig.updater.process_now(&first);
    assert_eq!(rig.launcher.started.lock().unwrap().len(), 1);
    assert!(!rig.world.layout.staging("99.1.0").exists());

    // A refusal is answered once, even if the server keeps offering the same release.
    let rig = Rig::new();
    let older = directive_json(&publish(
        &rig.fetch,
        &rig.world.key,
        "0.0.1",
        &binary(100),
        9,
    ));
    rig.updater.process_now(&older);
    PendingResult::remove(rig.world.state()).unwrap();
    rig.updater.process_now(&older);
    assert!(
        rig.world.pending().is_none(),
        "the same offer is not answered again"
    );
}

#[test]
fn a_download_that_keeps_failing_is_retried_and_then_reported() {
    let rig = Rig::new();
    let offer = rig.offer(NEW, 5);
    for attempt in 1..MAX_ATTEMPTS {
        rig.fetch.errors.lock().unwrap().insert(
            offer["manifest_url"].as_str().unwrap().to_owned(),
            FetchError::Transient("cannot reach the download address".into()),
        );
        rig.updater.process_now(&offer);
        assert!(
            rig.world.pending().is_none(),
            "attempt {attempt} is only retried"
        );
    }
    rig.fetch.errors.lock().unwrap().insert(
        offer["manifest_url"].as_str().unwrap().to_owned(),
        FetchError::Transient("cannot reach the download address".into()),
    );
    rig.updater.process_now(&offer);
    let result = rig
        .world
        .pending()
        .expect("reported after the last attempt");
    assert!(result.reason.unwrap().contains("after 5 attempts"));
}

#[test]
fn the_first_acknowledged_heartbeat_of_the_new_version_writes_the_marker() {
    let rig = Rig::new();
    let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_268_800);
    // No update: nothing is written.
    rig.updater.on_first_ack(wall);
    assert!(Marker::read(rig.world.state()).unwrap().is_none());

    // An update to another version, or one not yet switched, is not confirmed by this version.
    let mut record = rig.world.stage_release(NEW, &binary(100), 5);
    record.phase = Phase::Switched;
    record.write(rig.world.state()).unwrap();
    rig.updater.on_first_ack(wall);
    assert!(Marker::read(rig.world.state()).unwrap().is_none());

    // This version is the one being installed: it confirms, for that rollout and version.
    let mut record = rig.world.stage_release(AGENT_VERSION, &binary(100), 6);
    record.version = AGENT_VERSION.to_owned();
    record.from_version = "0.0.1".into();
    record.phase = Phase::Switched;
    record.write(rig.world.state()).unwrap();
    rig.updater.on_first_ack(wall);
    let marker = Marker::read(rig.world.state()).unwrap().unwrap();
    assert_eq!(
        (marker.rollout_id, marker.version.as_str()),
        (6, AGENT_VERSION)
    );
    assert!(marker.confirms(&record));
    assert!(rig.world.state().join(MARKER_FILE).is_file());
}

// --- Results --------------------------------------------------------------------------------------

fn pending(rig: &Rig, outcome: Outcome, reason: Option<&str>) -> PendingResult {
    let result = PendingResult {
        report_id: "00000000-0000-4000-8000-000000000042".into(),
        rollout_id: 5,
        version: NEW.into(),
        outcome,
        reason: reason.map(str::to_owned),
        occurred_at: "2026-01-01T12:05:00.000Z".into(),
    };
    result.write(rig.world.state()).unwrap();
    result
}

#[test]
fn every_outcome_is_posted_as_the_contract_says_and_then_forgotten() {
    for (outcome, reason) in [
        (Outcome::Succeeded, None),
        (Outcome::Failed, Some("the checksum does not match")),
        (
            Outcome::RolledBack,
            Some("no acknowledged heartbeat within 300 seconds"),
        ),
    ] {
        let rig = Rig::new();
        pending(&rig, outcome, reason);
        let transport = FakeTransport::new(vec![]);
        transport.set_accepting(true);
        rig.updater.tick(&transport);
        let sent = transport.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, RESULTS_PATH);
        assert_conforms("v1", "update-result.request", &sent[0].1);
        assert_eq!(sent[0].1["outcome"], outcome.as_str());
        assert_eq!(sent[0].1["agent_version"], AGENT_VERSION);
        assert!(rig.world.pending().is_none());
        // Nothing waiting: nothing is sent.
        rig.updater.tick(&transport);
        assert_eq!(transport.sent().len(), 1);
    }
}

#[test]
fn a_result_is_retried_with_the_same_report_id_until_the_server_accepts_it() {
    let rig = Rig::new();
    let result = pending(&rig, Outcome::RolledBack, Some("it did not confirm"));
    let transport = FakeTransport::new(vec![
        Err(ApiError::Transport("connection refused".into())),
        Err(ApiError::Server {
            status: 503,
            request_id: None,
        }),
        Err(ApiError::Unauthorized { request_id: None }),
        Err(ApiError::RateLimited {
            retry_after: None,
            request_id: None,
        }),
    ]);
    for _ in 0..4 {
        rig.updater.tick(&transport);
        assert_eq!(
            rig.world.pending().as_ref(),
            Some(&result),
            "kept for the next round"
        );
    }
    transport.push_with(accepted);
    rig.updater.tick(&transport);
    assert!(rig.world.pending().is_none());
    let sent = transport.sent();
    assert_eq!(sent.len(), 5);
    assert!(
        sent.iter()
            .all(|(_, body)| body["report_id"] == result.report_id)
    );
}

#[test]
fn a_result_the_server_will_never_accept_is_dropped() {
    let rig = Rig::new();
    pending(&rig, Outcome::Failed, Some("x"));
    let transport = FakeTransport::new(vec![Err(ApiError::Rejected {
        status: 400,
        code: "validation_failed".into(),
        message: "the rollout is not this host's".into(),
        request_id: None,
    })]);
    rig.updater.tick(&transport);
    assert!(rig.world.pending().is_none());
    assert_eq!(transport.sent().len(), 1);
}

#[test]
fn a_result_survives_a_restart_of_the_agent() {
    // The record is on disk: a new Updater (a restarted agent) sends it.
    let rig = Rig::new();
    let result = pending(&rig, Outcome::RolledBack, Some("it did not confirm"));
    let again = Rig::new();
    result.write(again.world.state()).unwrap();
    let transport = FakeTransport::new(vec![]);
    transport.set_accepting(true);
    again.updater.tick(&transport);
    assert_eq!(transport.sent()[0].1["report_id"], result.report_id);
}

// --- A supervisor that died -----------------------------------------------------------------------

#[test]
fn the_watchdog_does_not_race_this_process_handing_an_update_over() {
    // The worker writes the record and then starts the supervisor; a heartbeat in between must not
    // take the record for one whose supervisor died and start a second one.
    let rig = Rig::new();
    let mut record = rig.world.stage_release(NEW, &binary(100), 5);
    record.started_unix = unix(SystemTime::now());
    record.write(rig.world.state()).unwrap();
    rig.updater.inner.busy.store(true, Ordering::SeqCst);
    rig.updater.tick(&FakeTransport::new(vec![]));
    assert!(rig.launcher.started.lock().unwrap().is_empty());
    rig.updater.inner.busy.store(false, Ordering::SeqCst);
    rig.updater.tick(&FakeTransport::new(vec![]));
    assert_eq!(rig.launcher.started.lock().unwrap().len(), 1);
}

#[test]
fn an_update_without_a_supervisor_gets_one_and_a_live_supervisor_is_left_alone() {
    let rig = Rig::new();
    let mut record = rig.world.stage_release(NEW, &binary(100), 5);
    record.phase = Phase::Switched;
    record.write(rig.world.state()).unwrap();
    let transport = FakeTransport::new(vec![]);

    // A supervisor holds the lock: nothing is started.
    let held = Lock::file(&rig.world.state().join(LOCK_FILE))
        .unwrap()
        .unwrap();
    rig.updater.tick(&transport);
    assert!(rig.launcher.started.lock().unwrap().is_empty());
    drop(held);

    // It died (or the VM rebooted): one is started from the version being replaced, once.
    rig.updater.tick(&transport);
    rig.updater.tick(&transport);
    assert_eq!(
        rig.launcher.started.lock().unwrap().clone(),
        [(
            rig.world.layout.binary(old()),
            PathBuf::from("/etc/fleet-agent/config.toml")
        )]
    );
}

#[test]
fn an_update_that_never_finishes_is_given_up_after_a_day() {
    let rig = Rig::new();
    let mut record = rig.world.stage_release(NEW, &binary(100), 5);
    record.started_unix = 1;
    record.write(rig.world.state()).unwrap();
    rig.updater.tick(&FakeTransport::new(vec![]));
    assert!(Record::read(rig.world.state()).unwrap().is_none());
    let result = rig.world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::Failed);
    assert_eq!(result.report_id, record.report_id);
    assert!(!rig.world.layout.staging(NEW).exists());
}

#[test]
fn a_day_old_update_that_switched_is_never_dropped_but_handed_to_a_supervisor() {
    // Point 3 of the review of #85: whatever its age, an update past the switch keeps its record, so
    // the supervisor can roll back the unconfirmed version; only a provably pre-switch one is given up.
    for phase in [
        Phase::Switching,
        Phase::Switched,
        Phase::RollingBack,
        Phase::Confirmed,
    ] {
        let rig = Rig::new();
        let mut record = rig.world.stage_release(NEW, &binary(100), 5);
        record.started_unix = 1;
        record.phase = phase;
        record.write(rig.world.state()).unwrap();
        if phase == Phase::Switching {
            // Switching with `current` already swapped: the switch happened.
            fs::create_dir_all(rig.world.layout.version_dir(NEW)).unwrap();
            crate::fsx::replace_symlink(
                &rig.world.layout.current(),
                &Path::new("versions").join(NEW),
            )
            .unwrap();
        }
        rig.updater.tick(&FakeTransport::new(vec![]));
        assert!(
            Record::read(rig.world.state()).unwrap().is_some(),
            "{phase:?}"
        );
        assert!(rig.world.pending().is_none(), "{phase:?}");
        assert_eq!(rig.launcher.started.lock().unwrap().len(), 1, "{phase:?}");
    }
}

#[test]
fn the_new_version_does_not_confirm_late_or_after_a_restart_of_the_vm() {
    let rig = Rig::new();
    let mut record = rig.world.stage_release(AGENT_VERSION, &binary(100), 6);
    record.from_version = "0.0.1".into();
    record.phase = Phase::Switched;
    record.deadline_unix = Some(1_767_268_800);
    record.write(rig.world.state()).unwrap();
    let at = |unix: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(unix);

    // After the deadline: no marker.
    rig.updater.on_first_ack(at(1_767_268_801));
    assert!(Marker::read(rig.world.state()).unwrap().is_none());

    // From another boot than the update's: no marker.
    record.boot_id = Some("boot-0".into());
    record.write(rig.world.state()).unwrap();
    rig.updater.on_first_ack(at(1_767_268_700));
    assert!(Marker::read(rig.world.state()).unwrap().is_none());

    // In time, in the same boot: the marker carries the time of the acknowledgement and the boot.
    record.boot_id = Some(BOOT.into());
    record.write(rig.world.state()).unwrap();
    rig.updater.on_first_ack(at(1_767_268_700));
    let marker = Marker::read(rig.world.state()).unwrap().unwrap();
    assert_eq!(marker.confirmed_unix, 1_767_268_700);
    assert_eq!(marker.boot_id.as_deref(), Some(BOOT));
    assert!(marker.confirms(&record));
}

#[test]
fn install_and_uninstall_are_refused_while_an_update_is_in_progress() {
    let world = World::new();
    // No update: the lock is taken and held.
    let held = hold_for_install(world.state()).unwrap().expect("a lock");
    assert!(
        Lock::file(&world.state().join(layout::LOCK_FILE))
            .unwrap()
            .is_none()
    );
    drop(held);
    // A supervisor is running.
    let supervisor = Lock::file(&world.state().join(layout::LOCK_FILE))
        .unwrap()
        .unwrap();
    assert!(
        hold_for_install(world.state())
            .unwrap_err()
            .contains("in progress")
    );
    drop(supervisor);
    // An update is recorded, whatever its phase.
    world.stage_release(NEW, &binary(100), 5);
    let why = hold_for_install(world.state()).unwrap_err();
    assert!(why.contains("update to 99.0.0 is in progress"), "{why}");
    // No state directory: nothing to hold.
    assert!(
        hold_for_install(&world.state().join("absent"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_damaged_record_does_not_block_updates_forever() {
    let rig = Rig::new();
    fs::write(rig.world.state().join(RECORD_FILE), "{broken").unwrap();
    rig.updater.tick(&FakeTransport::new(vec![]));
    assert!(!rig.world.state().join(RECORD_FILE).exists());
    assert!(!rig.world.state().join(RESULT_FILE).exists());
}

// --- NFR-5: an agent below the minimum version ------------------------------------------------------

/// A server whose minimum agent version is above this agent's: everything but the update path says
/// `426`. Records which endpoints the update path used.
struct BelowMinimum {
    paths: Mutex<Vec<String>>,
    directive: Value,
}

impl Transport for BelowMinimum {
    fn post(&self, path: &str, body: &Value) -> Result<ApiResponse, ApiError> {
        self.paths.lock().unwrap().push(path.to_owned());
        match path {
            "/api/v1/heartbeat" => ok(json!({
                "server_time": "2026-01-01T12:00:00Z",
                "directives": {"agent_update": self.directive}
            })),
            RESULTS_PATH => accepted(body),
            _ => Err(ApiError::AgentVersionUnsupported {
                message: "minimum agent version is 99.0.0".into(),
                request_id: None,
            }),
        }
    }
}

#[test]
fn an_agent_below_the_minimum_version_still_receives_installs_and_reports_an_update() {
    use crate::config::Interval;
    use crate::report::{Heartbeat, Intervals};
    use crate::retry::{Backoff, RetryPolicy, SplitMix64};

    // The server (P1-UPDATES) exempts the heartbeat, update results, and release downloads from the
    // minimum version; this agent must need nothing else. The release it is offered is refused
    // (older), so the whole path to a reported result runs without a supervisor.
    let rig = Rig::new();
    let offer = directive_json(&publish(
        &rig.fetch,
        &rig.world.key,
        "0.0.1",
        &binary(100),
        9,
    ));
    let server = BelowMinimum {
        paths: Mutex::new(Vec::new()),
        directive: offer,
    };
    let secs = Duration::from_secs;
    let intervals = Intervals::new(
        Interval {
            start: secs(60),
            min: secs(30),
            max: secs(600),
        },
        Interval {
            start: secs(900),
            min: secs(300),
            max: secs(21_600),
        },
    );
    let mut heartbeat = Heartbeat::new(
        &intervals,
        Backoff::new(RetryPolicy::default(), SplitMix64::new(1)),
        SplitMix64::new(2),
        Instant::now(),
    )
    .with_updater(&rig.updater);
    heartbeat.beat(&server, None, Instant::now(), SystemTime::now());
    // The download and verification run on a thread of their own.
    let deadline = Instant::now() + secs(10);
    while rig.world.pending().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    rig.updater.tick(&server);

    assert!(rig.world.pending().is_none(), "the result was accepted");
    let paths = server.paths.lock().unwrap().clone();
    assert_eq!(paths, ["/api/v1/heartbeat", RESULTS_PATH]);
    // The downloads were plain GETs of the release files: no credential, no minimum-version check.
    let requested: Vec<String> = rig
        .fetch
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|(url, _)| url.clone())
        .collect();
    assert!(
        requested.iter().all(|url| url.starts_with(BASE)),
        "{requested:?}"
    );
}

#[test]
fn the_directive_helper_matches_the_contract_fields() {
    let d = directive("1.2.3", 4);
    let value = directive_json(&d);
    let envelope =
        json!({"server_time": "2026-01-01T12:00:00Z", "directives": {"agent_update": value}});
    assert_conforms("v1", "heartbeat.response", &envelope);
    assert!(Directive::parse(&value).is_some());
}
