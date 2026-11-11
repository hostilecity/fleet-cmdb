//! The poller against a scripted server and a counting executor. The server here is deliberately
//! worse than the real one: it redelivers a claimed task on every poll until a result arrives, even
//! after `start` (C7, R2), so only the agent's ledger stands between a redelivery and a second run.
//!
//! A "crash" is the poller stopping at a [`Point`] and being dropped with nothing more written, then a
//! new poller opening the same state directory, as a restarted agent would. Each step it relies on is
//! flushed before the call that wrote it returns, so this is what a kill at that point leaves on disk.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::*;
use crate::collect::contract::assert_conforms;
use crate::retry::{RetryPolicy, SplitMix64};
use crate::tasks::executor::Execution;
use crate::tasks::ledger::{DAMAGED_FILE, LEDGER_FILE};
use crate::test_support::TempDir;
use crate::update::record::StateFile;

thread_local! {
    static CRASH: Cell<Option<Point>> = const { Cell::new(None) };
    static CRASHED: Cell<bool> = const { Cell::new(false) };
}

/// Where a test makes the poller stop as if the agent were killed: just after this step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    /// `received` is on disk; nothing was decided.
    Received,
    /// `started` is on disk; `start` was not sent.
    Started,
    /// The server accepted `start`; the task did not run.
    Acknowledged,
    /// The task ran; `finished` was not written.
    Ran,
    /// `finished` is on disk; the result was not sent.
    Finished,
}

/// Whether the poller should stop here (tests only). Once it has, every later point stops too.
pub fn crash_at(point: Point) -> bool {
    let crash = CRASHED.with(Cell::get) || CRASH.with(|c| c.get() == Some(point));
    if crash {
        CRASHED.with(|c| c.set(true));
    }
    crash
}

/// Whether the poller stopped at a crash point.
pub fn crashed() -> bool {
    CRASHED.with(Cell::get)
}

fn crash_next_at(point: Option<Point>) {
    CRASH.with(|c| c.set(point));
    CRASHED.with(|c| c.set(false));
}

const A: &str = "0b5c8a4e-1d6f-4a3b-9c2d-7e8f9a0b1c2d";
const B: &str = "1c6d9b5f-2e7a-4b4c-8d3e-8f9a0b1c2d3e";

fn task(id: &str, task_type: &str, parameters: Value) -> Delivered {
    Delivered {
        id: id.into(),
        task_type: task_type.into(),
        parameters,
        timeout_seconds: 300,
        catalog_version: 1,
    }
}

fn restart(id: &str) -> Delivered {
    task(id, "restart_service", json!({"service": "nginx.service"}))
}

/// A server that queues tasks and redelivers the claimed one until a result arrives.
#[derive(Default)]
struct Server {
    queue: RefCell<VecDeque<Delivered>>,
    claimed: RefCell<Option<Delivered>>,
    polls: Cell<usize>,
    starts: RefCell<Vec<String>>,
    results: RefCell<Vec<(String, Value)>>,
    fail_polls: Cell<u32>,
    fail_starts: Cell<u32>,
    start_error: RefCell<Option<ApiError>>,
    fail_results: Cell<u32>,
    reject_start: Cell<bool>,
    /// The state `start` answers with when it rejects (`cancelled` unless set).
    reject_start_state: RefCell<Option<String>>,
    reject_result: Cell<bool>,
    poll_seconds: Cell<Option<u64>>,
    progress: RefCell<Vec<String>>,
    cancel: Cell<bool>,
}

impl Server {
    fn with(tasks: Vec<Delivered>) -> Self {
        let server = Self::default();
        server.queue.borrow_mut().extend(tasks);
        server
    }

    fn results(&self) -> Vec<(String, Value)> {
        self.results.borrow().clone()
    }

    fn down() -> ApiError {
        ApiError::Transport("connection refused".into())
    }
}

impl Server {
    fn poll_task(&self) -> Result<wire::PollReply, ApiError> {
        self.polls.set(self.polls.get() + 1);
        if self.fail_polls.get() > 0 {
            self.fail_polls.set(self.fail_polls.get() - 1);
            return Err(Self::down());
        }
        let mut claimed = self.claimed.borrow_mut();
        if claimed.is_none() {
            *claimed = self.queue.borrow_mut().pop_front();
        }
        Ok(claimed.clone().into())
    }
}

impl TaskApi for Server {
    fn poll(&self) -> Result<wire::PollReply, ApiError> {
        let mut reply = self.poll_task()?;
        reply.poll_seconds = self.poll_seconds.get();
        Ok(reply)
    }

    fn progress(&self, id: &str, percent: Option<u8>) -> Result<wire::ProgressReply, ApiError> {
        assert!(percent.is_none_or(|p| p <= 100));
        self.progress.borrow_mut().push(id.into());
        Ok(wire::ProgressReply {
            state: "running".into(),
            cancel: self.cancel.get(),
        })
    }

    fn start(&self, id: &str, started_at: &str) -> Result<Reply, ApiError> {
        assert!(
            started_at.ends_with('Z') && started_at.len() == 24,
            "{started_at}"
        );
        if let Some(error) = self.start_error.borrow().clone() {
            return Err(error);
        }
        if self.fail_starts.get() > 0 {
            self.fail_starts.set(self.fail_starts.get() - 1);
            return Err(Self::down());
        }
        if self.reject_start.get() {
            let state = self
                .reject_start_state
                .borrow()
                .clone()
                .unwrap_or_else(|| "cancelled".into());
            // A requeued task stays this host's to be delivered again; a cancelled one is gone.
            if state != "queued" {
                *self.claimed.borrow_mut() = None;
            }
            return Ok(Reply::Rejected(state));
        }
        self.starts.borrow_mut().push(id.into());
        Ok(Reply::Accepted)
    }

    fn result(&self, id: &str, body: &Value) -> Result<Reply, ApiError> {
        if self.fail_results.get() > 0 {
            self.fail_results.set(self.fail_results.get() - 1);
            return Err(Self::down());
        }
        self.results.borrow_mut().push((id.into(), body.clone()));
        let mut claimed = self.claimed.borrow_mut();
        if claimed.as_ref().is_some_and(|t| t.id == id) {
            *claimed = None;
        }
        if self.reject_result.get() {
            return Ok(Reply::Rejected("conflict".into()));
        }
        Ok(Reply::Accepted)
    }
}

/// Counts every run, per task id: the canary that proves what was executed.
struct Counting {
    implements: Vec<&'static str>,
    runs: Mutex<HashMap<String, u32>>,
    /// `run` returns `None`, as when a unit is left running at shutdown.
    detach: std::sync::atomic::AtomicBool,
    /// What `recover` answers.
    recovered: Mutex<Option<crate::tasks::executor::Recovered>>,
    /// Whether the control said cancel during the run.
    saw_cancel: std::sync::atomic::AtomicBool,
}

impl Counting {
    fn new(implements: &[&'static str]) -> Self {
        Self {
            implements: implements.to_vec(),
            runs: Mutex::default(),
            detach: Default::default(),
            recovered: Mutex::default(),
            saw_cancel: Default::default(),
        }
    }

    fn runs(&self, id: &str) -> u32 {
        self.runs.lock().unwrap().get(id).copied().unwrap_or(0)
    }

    fn total(&self) -> u32 {
        self.runs.lock().unwrap().values().sum()
    }
}

impl Executor for Counting {
    fn implements(&self, task_type: &str) -> bool {
        self.implements.contains(&task_type)
    }

    fn check(&self, task: &Delivered) -> Result<(), &'static str> {
        if task.parameters.get("bad").is_some() {
            return Err(reason::INVALID_PARAMS);
        }
        Ok(())
    }

    fn recover(&self, _: &crate::tasks::ledger::Task) -> crate::tasks::executor::Recovered {
        self.recovered
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(crate::tasks::executor::Recovered::Nothing)
    }

    fn run(&self, task: &Delivered, control: &dyn Control) -> Option<Execution> {
        if control.cancel_requested() {
            self.saw_cancel
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if self.detach.load(std::sync::atomic::Ordering::SeqCst) {
            *self
                .runs
                .lock()
                .unwrap()
                .entry(task.id.clone())
                .or_insert(0) += 1;
            return None;
        }
        *self
            .runs
            .lock()
            .unwrap()
            .entry(task.id.clone())
            .or_insert(0) += 1;
        Some(Execution {
            outcome: Outcome::Succeeded,
            reason: None,
            exit_status: Some(0),
            started_at: wall(),
            finished_at: wall() + Duration::from_secs(2),
            output: "restarted\n".into(),
            output_truncated: false,
            details: serde_json::Map::new(),
        })
    }
}

fn wall() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_767_268_800)
}

fn settings(text: &str) -> TaskSettings {
    let table: toml::Table = toml::from_str(text).unwrap();
    TaskSettings::from_value(table.get("tasks"))
}

fn all_enabled() -> TaskSettings {
    settings(
        "[tasks]\nenabled = [\"refresh_reports\", \"restart_service\"]\nallowed_services = [\"nginx.service\"]\n",
    )
}

fn interval() -> Interval {
    Interval {
        start: Duration::from_secs(30),
        min: Duration::from_secs(10),
        max: Duration::from_secs(300),
    }
}

struct Rig {
    _tmp: TempDir,
    dir: PathBuf,
    settings: TaskSettings,
    shutdown: Shutdown,
    hint: TaskHint,
}

impl Rig {
    fn new(settings: TaskSettings) -> Self {
        let tmp = TempDir::new();
        let dir = tmp.path("state");
        crate::state::ensure_dir(&dir).unwrap();
        Self {
            _tmp: tmp,
            dir,
            settings,
            shutdown: Shutdown::default(),
            hint: TaskHint::default(),
        }
    }

    fn poller<'a>(
        &'a self,
        executor: &'a dyn Executor,
        updater: Option<&'a Updater>,
    ) -> Poller<'a, SplitMix64> {
        let policy = RetryPolicy {
            base: Duration::from_millis(1),
            cap: Duration::from_millis(2),
            ..RetryPolicy::default()
        };
        Poller::new(
            &self.dir,
            &self.settings,
            executor,
            updater,
            &self.shutdown,
            &self.hint,
            interval(),
            Backoff::new(policy, SplitMix64::new(1)),
        )
    }
}

/// Ticks `poller` `n` times, a poll interval apart, so every tick may poll.
fn ticks(poller: &mut Poller<'_, SplitMix64>, server: &Server, n: usize) {
    let start = Instant::now();
    for i in 0..n {
        poller.tick(
            server,
            start + Duration::from_secs(31 * i as u64 + 1),
            wall(),
        );
    }
}

#[test]
fn a_task_runs_once_after_started_and_the_servers_acceptance_and_its_result_is_reported() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 3);
    assert_eq!(executor.runs(A), 1);
    assert_eq!(*server.starts.borrow(), [A]);
    let results = server.results();
    assert_eq!(results.len(), 1);
    let (id, body) = &results[0];
    assert_eq!(id, A);
    assert_eq!(body["outcome"], "succeeded");
    assert_eq!(body["exit_status"], 0);
    assert_eq!(body["output"], "restarted\n");
    assert_eq!(
        poller.ledger().unwrap().task(A).unwrap().state,
        State::Reported
    );
}

#[test]
fn duplicate_delivery_of_one_id_runs_it_once() {
    // P3-A02 AC: the server sends the same id again (after a result, and in another process).
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A), restart(A), restart(A)]);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 4);
    drop(poller);
    server.queue.borrow_mut().push_back(restart(A));
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 3);
    assert_eq!(executor.runs(A), 1);
    assert_eq!(server.starts.borrow().len(), 1);
    // Each later delivery of the id is closed, never run: it ran, so `failed`/`agent_error` ("ran,
    // or may have run"), which a server that really held it claimed would accept (#31).
    let results = server.results();
    assert_eq!(results[0].1["outcome"], "succeeded");
    assert!(results.len() > 1);
    for (id, body) in &results[1..] {
        assert_eq!(id, A);
        assert_eq!(
            (&body["outcome"], &body["reason"]),
            (&json!("failed"), &json!("agent_error"))
        );
    }
}

/// Runs task A up to `point`, "kills" the agent there, and restarts it with the server still
/// redelivering A. Returns the executor's run count, what the server received, and the starts.
fn crash_and_restart(point: Point) -> (u32, Vec<(String, Value)>, Vec<String>) {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    crash_next_at(Some(point));
    let mut poller = rig.poller(&executor, None);
    poller.tick(&server, Instant::now(), wall());
    assert!(crashed(), "{point:?} was reached");
    drop(poller);
    crash_next_at(None);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 4);
    let results = server.results();
    let starts = server.starts.borrow().clone();
    (executor.total(), results, starts)
}

#[test]
fn killed_after_received_reports_not_run_and_never_runs_it() {
    // `start` was never sent, so the server holds it claimed and accepts `not_run` (#31).
    let (runs, results, starts) = crash_and_restart(Point::Received);
    assert_eq!(runs, 0);
    assert!(starts.is_empty());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1["outcome"], "failed");
    assert_eq!(results[0].1["reason"], "not_run");
}

#[test]
fn killed_after_started_reports_interrupted_and_never_runs_it() {
    // AC-3.3, P3-A02 AC: killed after `started` is written.
    for point in [Point::Started, Point::Acknowledged] {
        let (runs, results, _) = crash_and_restart(point);
        assert_eq!(runs, 0, "{point:?}");
        assert_eq!(results.len(), 1, "{point:?}");
        assert_eq!(results[0].0, A);
        assert_eq!(results[0].1["outcome"], "failed", "{point:?}");
        assert_eq!(results[0].1["reason"], "interrupted", "{point:?}");
        assert!(results[0].1["started_at"].is_string(), "{point:?}");
    }
}

#[test]
fn killed_mid_run_reports_interrupted_and_never_runs_it_again() {
    let (runs, results, starts) = crash_and_restart(Point::Ran);
    assert_eq!(runs, 1, "the one run before the kill");
    assert_eq!(starts.len(), 1);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1["reason"], "interrupted");
}

#[test]
fn killed_after_finished_sends_the_stored_result_unchanged() {
    let (runs, results, _) = crash_and_restart(Point::Finished);
    assert_eq!(runs, 1);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1["outcome"], "succeeded");
    assert_eq!(results[0].1["output"], "restarted\n");
}

#[test]
fn a_result_is_retried_until_accepted_with_the_same_body_across_a_restart() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.fail_results.set(3);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 2);
    drop(poller);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 4);
    assert_eq!(executor.runs(A), 1);
    let results = server.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1["output"], "restarted\n");
    assert!(server.claimed.borrow().is_none());
}

#[test]
fn every_local_refusal_is_reported_with_its_reason_and_nothing_starts() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let ids = [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000003",
        "00000000-0000-4000-8000-000000000004",
        "00000000-0000-4000-8000-000000000005",
    ];
    let server = Server::with(vec![
        task(ids[0], "reboot", json!({})),
        task(ids[1], "apply_package_updates", json!({})),
        task(ids[2], "refresh_reports", json!({})),
        task(ids[3], "restart_service", json!({"bad": true})),
        task(
            ids[4],
            "restart_service",
            json!({"service": "x".repeat(ledger::MAX_PARAMETERS_BYTES)}),
        ),
    ]);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 7);
    assert_eq!(executor.total(), 0);
    assert!(server.starts.borrow().is_empty());
    let got: Vec<(String, String, String)> = server
        .results()
        .into_iter()
        .map(|(id, body)| {
            (
                id,
                body["outcome"].as_str().unwrap().to_owned(),
                body["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected = [
        "unknown_type",
        "not_enabled_locally",
        "not_supported",
        "invalid_params",
        "invalid_params",
    ];
    assert_eq!(got.len(), 5);
    for ((id, outcome, why), (want_id, want)) in got.iter().zip(ids.iter().zip(expected)) {
        assert_eq!(
            (id.as_str(), outcome.as_str(), why.as_str()),
            (*want_id, "refused", want)
        );
    }
    // None of them was recorded as started, so none can be reported `interrupted` later.
    for id in ids {
        assert!(!poller.ledger().unwrap().task(id).unwrap().started);
    }
}

#[test]
fn by_default_this_build_never_polls_and_would_refuse_anything_not_supported() {
    // This build implements only apply_package_updates (`tasks::IMPLEMENTED`), which is off unless
    // enabled locally (DEC-14), and refresh_reports, on by default, is not built yet: nothing to poll for.
    let rig = Rig::new(TaskSettings::default());
    let executor = super::super::executor::Registry::production(
        TaskSettings::default(),
        std::sync::Arc::new(crate::tasks::apply_updates::Ignored),
    );
    let server = Server::with(vec![task(A, "refresh_reports", json!({}))]);
    let mut poller = rig.poller(&executor, None);
    assert!(!poller.polls());
    rig.hint.raise();
    let wait = poller.tick(&server, Instant::now(), wall());
    assert_eq!(wait, IDLE);
    assert_eq!(server.polls.get(), 0);
    // The ledger is open (and the hint used up) all the same, so earlier tasks would be reported.
    assert!(rig.dir.join(LEDGER_FILE).exists());
    assert!(!rig.hint.take());
    // Should a task arrive anyway, it is refused before anything is recorded as started.
    assert_eq!(
        poller.refusal(&task(A, "refresh_reports", json!({})), wall()),
        Some((Outcome::Refused, reason::NOT_SUPPORTED))
    );
    // An update the owner has not enabled here is refused before anything is checked or run.
    assert_eq!(
        poller.refusal(&task(A, "apply_package_updates", json!({})), wall()),
        Some((Outcome::Refused, reason::NOT_ENABLED_LOCALLY))
    );
    // Once enabled, the agent polls.
    let enabled = settings("[tasks]\nenabled = [\"apply_package_updates\"]\n");
    let rig = Rig::new(enabled.clone());
    let executor = super::super::executor::Registry::production(
        enabled,
        std::sync::Arc::new(crate::tasks::apply_updates::Ignored),
    );
    assert!(rig.poller(&executor, None).polls());
}

#[test]
fn a_refused_start_runs_nothing() {
    // L3: cancelled between `started` and `start`.
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.reject_start.set(true);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 3);
    assert_eq!(executor.total(), 0);
    // It is recorded as not run and answered; there is no result to send (P3-S03).
    assert!(server.results().is_empty());
    assert_eq!(
        poller.ledger().unwrap().task(A).unwrap().state,
        State::Reported
    );
    // Delivered again, it is still never run.
    server.reject_start.set(false);
    server.queue.borrow_mut().push_back(restart(A));
    ticks(&mut poller, &server, 2);
    assert_eq!(executor.total(), 0);
}

#[test]
fn start_is_retried_and_the_task_runs_only_once_accepted() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.fail_starts.set(2);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 2);
    assert_eq!(executor.runs(A), 1);
    assert_eq!(server.starts.borrow().len(), 1);
}

#[test]
fn a_result_the_server_refuses_for_good_is_dropped_and_the_task_still_never_reruns() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A), restart(B)]);
    server.reject_result.set(true);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 4);
    assert_eq!(executor.runs(A), 1);
    assert_eq!(executor.runs(B), 1);
    assert_eq!(server.results().len(), 2);
    server.queue.borrow_mut().push_back(restart(A));
    ticks(&mut poller, &server, 2);
    assert_eq!(executor.runs(A), 1);
}

#[test]
fn a_damaged_ledger_holds_every_task() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 2);
    drop(poller);
    let path = rig.dir.join(LEDGER_FILE);
    let mut text: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    text[0].insert(20, 'x');
    std::fs::write(&path, text.join("\n") + "\n").unwrap();

    server.queue.borrow_mut().push_back(restart(B));
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 3);
    assert!(rig.dir.join(DAMAGED_FILE).exists());
    assert_eq!(executor.runs(B), 0);
    let (id, body) = server.results().last().unwrap().clone();
    assert_eq!(id, B);
    // "Ran, or may have run": the lost records could have been this task's.
    assert_eq!(body["outcome"], "failed");
    assert_eq!(body["reason"], reason::AGENT_ERROR);
}

#[test]
fn polls_on_the_interval_and_at_once_on_a_hint() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::default();
    let mut poller = rig.poller(&executor, None);
    let t0 = Instant::now();
    poller.tick(&server, t0, wall());
    assert_eq!(server.polls.get(), 1);
    // Not again before the interval...
    poller.tick(&server, t0 + Duration::from_secs(10), wall());
    assert_eq!(server.polls.get(), 1);
    // ...unless a heartbeat says a task is waiting.
    rig.hint.raise();
    poller.tick(&server, t0 + Duration::from_secs(11), wall());
    assert_eq!(server.polls.get(), 2);
    poller.tick(&server, t0 + Duration::from_secs(40), wall());
    assert_eq!(server.polls.get(), 2);
    poller.tick(&server, t0 + Duration::from_secs(41), wall());
    assert_eq!(server.polls.get(), 3);
    // A wait never exceeds the hint check, so a hint is never missed for long.
    assert!(poller.tick(&server, t0 + Duration::from_secs(50), wall()) <= HINT_CHECK);
}

#[test]
fn every_body_sent_conforms_to_the_contract() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![
        restart(A),
        task(B, "reboot", json!({})),
        task(
            "00000000-0000-4000-8000-000000000003",
            "refresh_reports",
            json!({}),
        ),
    ]);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 5);
    let mut bodies: Vec<Value> = server.results().into_iter().map(|(_, b)| b).collect();
    for point in [Point::Received, Point::Started, Point::Ran, Point::Finished] {
        bodies.extend(crash_and_restart(point).1.into_iter().map(|(_, b)| b));
    }
    assert!(bodies.len() >= 7);
    for body in bodies {
        crate::collect::contract::assert_conforms("v1", "task-result.request", &body);
    }
}

#[test]
fn a_failed_poll_backs_off() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.fail_polls.set(1);
    let mut poller = rig.poller(&executor, None);
    let t0 = Instant::now();
    poller.tick(&server, t0, wall());
    assert_eq!(executor.total(), 0);
    poller.tick(&server, t0 + Duration::from_secs(1), wall());
    assert_eq!(executor.runs(A), 1);
}

#[test]
fn an_update_in_progress_blocks_polling_and_the_slot_is_free_after_the_task() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let updater = Updater::inert(&rig.dir);
    let server = Server::with(vec![restart(A)]);
    crate::update::record::tests::record()
        .write(&rig.dir)
        .unwrap();
    let mut poller = rig.poller(&executor, Some(&updater));
    ticks(&mut poller, &server, 2);
    assert_eq!(server.polls.get(), 0);
    crate::update::record::Record::remove(&rig.dir).unwrap();
    // The next poll is an interval after the last blocked one.
    ticks(&mut poller, &server, 4);
    assert_eq!(executor.runs(A), 1);
    assert!(updater.task_slot().is_ok());
}

#[test]
fn an_unusable_state_directory_means_no_poll() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    std::fs::remove_dir(&rig.dir).unwrap();
    let mut poller = rig.poller(&executor, None);
    assert_eq!(poller.tick(&server, Instant::now(), wall()), LEDGER_RETRY);
    assert_eq!(server.polls.get(), 0);
}

#[test]
fn a_known_id_delivered_again_waits_the_interval_instead_of_polling_in_a_loop() {
    // Review of #166.
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.reject_result.set(true);
    let mut poller = rig.poller(&executor, None);
    let t0 = Instant::now();
    poller.tick(&server, t0, wall());
    // The server keeps the claim and redelivers A, which this agent already has.
    *server.claimed.borrow_mut() = Some(restart(A));
    poller.tick(&server, t0 + Duration::from_secs(1), wall());
    let polls = server.polls.get();
    for s in 2..29 {
        poller.tick(&server, t0 + Duration::from_secs(s), wall());
    }
    assert_eq!(server.polls.get(), polls, "no poll before the interval");
    poller.tick(&server, t0 + Duration::from_secs(32), wall());
    assert_eq!(server.polls.get(), polls + 1);
    assert_eq!(executor.runs(A), 1);
}

#[test]
fn a_start_only_an_upgrade_can_fix_releases_the_task_slot_and_runs_nothing() {
    // Review of #166: a 426 on start must not hold back the update it needs.
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let updater = Updater::inert(&rig.dir);
    let server = Server::with(vec![restart(A)]);
    *server.start_error.borrow_mut() = Some(ApiError::AgentVersionUnsupported {
        message: "upgrade".into(),
        request_id: None,
    });
    let mut poller = rig.poller(&executor, Some(&updater));
    poller.tick(&server, Instant::now(), wall());
    assert_eq!(executor.total(), 0);
    assert!(
        updater.task_slot().is_ok(),
        "the slot is free for the update"
    );
    // After the upgrade (here: the error goes away), recovery reports it and it never runs.
    *server.start_error.borrow_mut() = None;
    let later = Instant::now() + Duration::from_secs(3600);
    for i in 0..3 {
        poller.tick(&server, later + Duration::from_secs(31 * i), wall());
    }
    assert_eq!(executor.total(), 0);
    let results = server.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1["reason"], "interrupted");
}

#[test]
fn a_result_rebuilt_from_the_ledger_is_stored_and_sent_unchanged() {
    // Review of #166: the same report_id and finished_at on every retry, across restarts.
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.fail_results.set(1);
    let mut poller = rig.poller(&executor, None);
    poller.tick(&server, Instant::now(), wall());
    drop(poller);
    std::fs::remove_file(rig.dir.join(ledger::RESULT_FILE)).unwrap();
    server.fail_results.set(2);
    let mut poller = rig.poller(&executor, None);
    poller.tick(&server, Instant::now(), wall());
    let stored = poller.ledger().unwrap().result(A).unwrap();
    drop(poller);
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 3);
    let results = server.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, stored);
    assert_eq!(executor.runs(A), 1);
}

#[test]
fn a_start_the_server_answers_queued_is_closed_not_run_and_never_run() {
    // #31, threat model L2: the claim lapsed before `start` arrived. The agent closes the task with
    // failed/not_run at once, and again if the server delivers it anyway; it never runs it.
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.reject_start.set(true);
    *server.reject_start_state.borrow_mut() = Some("queued".into());
    let mut poller = rig.poller(&executor, None);
    poller.tick(&server, Instant::now(), wall());
    assert_eq!(executor.total(), 0);
    let results = server.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1["outcome"], "failed");
    assert_eq!(results[0].1["reason"], "not_run");
    assert_eq!(results[0].1["started_at"], Value::Null);
    let task = poller.ledger().unwrap().task(A).unwrap().clone();
    assert_eq!(task.state, State::Reported);
    assert!(task.started && !task.executed);
    // Delivered again (the close was lost): closed again, with the same reason, and still not run.
    server.reject_start.set(false);
    server.queue.borrow_mut().push_back(restart(A));
    ticks(&mut poller, &server, 2);
    assert_eq!(executor.total(), 0);
    let results = server.results();
    assert_eq!(results.len(), 2);
    assert_eq!(results[1].1["reason"], "not_run");
    for (_, body) in results {
        assert_conforms("v1", "task-result.request", &body);
    }
}

#[test]
fn the_servers_poll_hint_sets_the_interval_within_the_configured_bounds() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::default();
    server.poll_seconds.set(Some(120));
    let mut poller = rig.poller(&executor, None);
    let t0 = Instant::now();
    poller.tick(&server, t0, wall());
    for s in 1..120 {
        poller.tick(&server, t0 + Duration::from_secs(s), wall());
    }
    assert_eq!(
        server.polls.get(),
        1,
        "the 120 s hint replaced the 30 s interval"
    );
    poller.tick(&server, t0 + Duration::from_secs(121), wall());
    assert_eq!(server.polls.get(), 2);
    // Above the configured maximum (300 s): clamped to it.
    server.poll_seconds.set(Some(300));
    drop(poller);
    let mut poller = rig.poller(&executor, None);
    poller.tick(&server, t0, wall());
    assert_eq!(poller.interval(), Duration::from_secs(300));
}

#[test]
fn a_running_task_sends_progress_and_hears_the_servers_cancel() {
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    let server = Server::with(vec![restart(A)]);
    server.cancel.set(true);
    let mut poller = rig.poller(&executor, None);
    poller.set_progress_every(Duration::from_millis(1));
    poller.tick(&server, Instant::now(), wall());
    assert_eq!(*server.progress.borrow(), [A]);
    assert!(
        executor
            .saw_cancel
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert!(poller.ledger().unwrap().task(A).unwrap().executed);
}

#[test]
fn a_task_left_running_in_its_unit_is_waited_for_after_a_restart_and_then_reported() {
    // Threat model L8: the agent stopped while a task that cannot be interrupted ran on.
    use crate::tasks::executor::Recovered;
    let rig = Rig::new(all_enabled());
    let executor = Counting::new(&["restart_service"]);
    executor
        .detach
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let server = Server::with(vec![restart(A), restart(B)]);
    let mut poller = rig.poller(&executor, None);
    poller.tick(&server, Instant::now(), wall());
    assert!(
        server.results().is_empty(),
        "nothing is reported for a task still running"
    );
    drop(poller);
    // Restarted: the unit still runs, so nothing is reported and nothing new is polled.
    executor
        .detach
        .store(false, std::sync::atomic::Ordering::SeqCst);
    *executor.recovered.lock().unwrap() = Some(Recovered::Running);
    *server.claimed.borrow_mut() = None;
    let polls = server.polls.get();
    let mut poller = rig.poller(&executor, None);
    let wait = poller.tick(&server, Instant::now(), wall());
    assert_eq!(wait, RECOVERY_CHECK);
    assert_eq!(server.polls.get(), polls);
    assert!(server.results().is_empty());
    // It ended: what it did is reported, then polling resumes.
    *executor.recovered.lock().unwrap() = Some(Recovered::Ended(Execution {
        outcome: Outcome::Failed,
        reason: Some("nonzero_exit"),
        exit_status: Some(100),
        started_at: wall(),
        finished_at: wall() + Duration::from_secs(60),
        output: "E: broken\n".into(),
        output_truncated: false,
        details: serde_json::Map::new(),
    }));
    ticks(&mut poller, &server, 2);
    let results = server.results();
    assert_eq!(results[0].0, A);
    assert_eq!(results[0].1["exit_status"], 100);
    assert_eq!(results[0].1["output"], "E: broken\n");
    assert_eq!(executor.runs(A), 1);
    assert_eq!(executor.runs(B), 1);
}

#[test]
fn a_canary_proves_refused_tasks_run_nothing_and_an_accepted_one_runs() {
    // AC-3.1 (agent half), P3-A03 AC: the real registry and spawn path, with a test type whose only
    // effect is creating a canary file.
    use crate::tasks::catalog::Privilege;
    use crate::tasks::executor::tests::{Fixed, fake_units, leak, program, registry};
    let tmp = TempDir::new();
    let canary = tmp.path("canary");
    let touch = || {
        program(
            "/usr/bin/touch",
            Box::leak(vec![leak(canary.display().to_string())].into_boxed_slice()),
            Privilege::ReadOnly,
        )
    };
    let restart = Fixed {
        type_id: "restart_service",
        programs: vec![touch()],
        service: true,
    };
    let executor = registry(
        vec![Fixed::new("refresh_reports", vec![touch()]), restart],
        fake_units(),
    );
    let rig = Rig::new(settings(
        "[tasks]\nenabled = [\"refresh_reports\"]\nallowed_services = [\"nginx.service\"]\n",
    ));
    let hostile = [
        task("00000000-0000-4000-8000-0000000000c1", "reboot", json!({})),
        task(
            "00000000-0000-4000-8000-0000000000c2",
            "refresh_reports",
            json!({"extra": true}),
        ),
        task(
            "00000000-0000-4000-8000-0000000000c3",
            "refresh_reports",
            json!({"command": "id"}),
        ),
        task(
            "00000000-0000-4000-8000-0000000000c4",
            "restart_service",
            json!({"service": "nginx.service"}),
        ),
        task(
            "00000000-0000-4000-8000-0000000000c5",
            "apply_package_updates",
            json!({}),
        ),
    ];
    let server = Server::with(hostile.to_vec());
    let mut poller = rig.poller(&executor, None);
    ticks(&mut poller, &server, 8);
    let results = server.results();
    let reasons: Vec<&str> = results
        .iter()
        .map(|(_, b)| b["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "unknown_type",
            "invalid_params",
            "invalid_params",
            "not_enabled_locally",
            "not_enabled_locally"
        ]
    );
    assert!(results.iter().all(|(_, b)| b["outcome"] == "refused"));
    assert!(server.starts.borrow().is_empty());
    assert!(!canary.exists(), "a refused task ran something");
    server
        .queue
        .borrow_mut()
        .push_back(task(B, "refresh_reports", json!({})));
    rig.hint.raise();
    ticks(&mut poller, &server, 2);
    assert!(canary.exists(), "the accepted task did not run");
    assert_eq!(server.results().last().unwrap().1["outcome"], "succeeded");
}
