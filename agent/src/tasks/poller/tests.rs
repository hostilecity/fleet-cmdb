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
    reject_result: Cell<bool>,
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

impl TaskApi for Server {
    fn poll(&self) -> Result<wire::PollReply, ApiError> {
        self.polls.set(self.polls.get() + 1);
        if self.fail_polls.get() > 0 {
            self.fail_polls.set(self.fail_polls.get() - 1);
            return Err(Self::down());
        }
        let mut claimed = self.claimed.borrow_mut();
        if claimed.is_none() {
            *claimed = self.queue.borrow_mut().pop_front();
        }
        Ok(claimed.clone())
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
            *self.claimed.borrow_mut() = None;
            return Ok(Reply::Rejected("cancelled".into()));
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
}

impl Counting {
    fn new(implements: &[&'static str]) -> Self {
        Self {
            implements: implements.to_vec(),
            runs: Mutex::default(),
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

    fn run(&self, task: &Delivered, _: &Shutdown) -> Execution {
        *self
            .runs
            .lock()
            .unwrap()
            .entry(task.id.clone())
            .or_insert(0) += 1;
        Execution {
            outcome: Outcome::Succeeded,
            reason: None,
            exit_status: Some(0),
            started_at: wall(),
            finished_at: wall() + Duration::from_secs(2),
            output: "restarted\n".into(),
            output_truncated: false,
            details: serde_json::Map::new(),
        }
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
    assert_eq!(
        server.results().len(),
        1,
        "nothing further is reported for it"
    );
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
fn killed_after_received_reports_interrupted_and_never_runs_it() {
    let (runs, results, starts) = crash_and_restart(Point::Received);
    assert_eq!(runs, 0);
    assert!(starts.is_empty());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1["outcome"], "failed");
    assert_eq!(results[0].1["reason"], "interrupted");
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
fn this_build_never_polls_and_would_refuse_anything_not_supported() {
    // No executor yet (P3-A03): no type is implemented, so there is nothing to poll for.
    let rig = Rig::new(TaskSettings::default());
    let executor = super::super::executor::NoExecutor;
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
