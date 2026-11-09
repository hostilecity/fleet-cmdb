//! The task poller (FR-3.2, FR-3.3, AC-3.3, P3-A02): polls the server for a task, records it in the
//! [`Ledger`], refuses what this agent will not run, and reports every result until it is accepted.
//!
//! **When it polls.** Only when the owner enabled a type that this agent implements ([`Poller::polls`]):
//! with nothing enabled and supported the server offers this host nothing (P3-A01), so there is nothing
//! to ask for. Then every poll interval (`[task_poll]` in the config, 30 s by default), and within
//! [`HINT_CHECK`] of a heartbeat carrying the `tasks_available` directive ([`TaskHint`]). After a failure it backs off as every other request does ([`Backoff`],
//! P1-A02). One task at a time: a task is handled to its end before the next poll.
//!
//! **What it does with a task.** In this order, stopping at the first that fails:
//!
//! 1. The id is not already in the ledger. A known id is never run again (duplicate delivery); if it
//!    is not reported yet, step 7 reports it. If it was reported (or dropped) and the server still
//!    delivers it, the server holds it as claimed, for example after a `start` that came too late and
//!    found the task back in the queue (P3-S05, threat model L2), and the result sent then was lost
//!    or refused. The agent closes it again with `failed`, which a claimed task accepts: reason
//!    `not_run` if the ledger shows it never ran (no `executing` record), `agent_error` ("ran, or may
//!    have run") otherwise. Without this the task would hold the host's single task slot until it
//!    expired.
//! 2. `received` is recorded.
//! 3. The local checks ([`Poller::refusal`]): no ledger hold (else `failed`, `agent_error`: the
//!    lost records could be this task's), the type is in the embedded catalog
//!    (`unknown_type`), enabled here (`not_enabled_locally`), implemented (`not_supported`), and the
//!    executor's own checks ([`Executor::check`]). A refusal is recorded `finished` and reported;
//!    nothing is started.
//! 4. `started` is recorded and flushed.
//! 5. `start` is sent; the task runs only after the server answers `run: true` (P3-S03). Any other
//!    answer is recorded as not run, and nothing runs. When the task went back to the queue (the claim
//!    lapsed before `start` arrived, P3-S05), the agent reports it `failed` with `not_run` at once,
//!    which the server accepts for a task this host claimed, so the host is not blocked until the task
//!    expires; otherwise (cancelled, gone) there is no result to send. A failed `start` is retried;
//!    nothing runs meanwhile.
//! 6. `executing` is recorded and flushed, the executor runs it ([`Executor::run`]) with a
//!    [`Control`] that sends progress every [`PROGRESS_EVERY`] and passes on the server's `cancel`
//!    (P3-S05), and the result is recorded `finished`. If the agent stops while a task that cannot be
//!    interrupted still runs in its own unit, nothing is recorded: the task stays `started`, and
//!    recovery deals with it.
//! 7. The result is sent until the server accepts it (or refuses it for good), then `reported`.
//!
//! In this build the executor ([`super::executor::Registry`], P3-A03) implements no type, so the poller
//! does not poll at all by default, and any task that does arrive stops at step 3 with
//! `not_supported`. Steps 4 to 6 are exercised by the tests with test executors.
//!
//! **Poll interval.** The poll response's `poll_seconds` (Settings: Tasks, #31) replaces the
//! configured interval, clamped to the configured `min_seconds` and `max_seconds`. A `cancel` in a
//! poll response names a running task; the poller polls only between tasks, so it has none, and the
//! directive is only logged (a running task gets it through progress).
//!
//! **Recovery.** On start, and whenever the ledger is reopened, every unreported task is reported
//! before anything is polled ([`Poller::reconcile`]):
//!
//! - `received` only: it never started, so nothing ran, but the id is in the ledger, so it is not run
//!   now either. Reported `failed` with reason `not_run`;
//! - `started` without `finished`: it may have run. Reported `failed` with reason `interrupted`, unless
//!   the stored result shows it finished, which is then sent as it was, or the executor finds part of
//!   it still running in its own unit ([`Executor::recover`], threat model L8): then nothing is polled
//!   until it ends, and what it did is reported;
//! - `finished` without `reported`: the stored result is sent again (idempotent on the server);
//! - an unknown state (a record this version cannot read): reported `failed`, `agent_error`, never run.
//!
//! **Updates.** The poller holds the updater's task slot from each poll to the end of the task it
//! claims, so an agent update waits for it; while an update is in progress (until confirmed or rolled
//! back), it does not poll (P1-AGENT-UPDATE, L7).
//!
//! **The journal.** Every decision is logged with the task id and type: received, refused and why,
//! started, finished, reported, and recovered (threat model A3). Parameters are not logged: the ledger
//! keeps them, readable only by root.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

use super::catalog::Catalog;
use super::executor::{Control, Delivered, Executor, Recovered};
use super::ledger::{self, Ledger, LedgerError, Outcome, Receipt, State, Task};
use super::settings::TaskSettings;
use super::wire::{self, Reply, TaskApi};
use crate::client::ApiError;
use crate::config::Interval;
use crate::report::rfc3339;
use crate::retry::{Backoff, RetryClass, Rng};
use crate::shutdown::Shutdown;
use crate::update::Updater;

/// How often the poller looks for a hint the heartbeat loop raised.
pub const HINT_CHECK: Duration = Duration::from_secs(5);
/// How long to wait before opening a ledger that could not be opened.
pub const LEDGER_RETRY: Duration = Duration::from_secs(60);
/// How long the poller sleeps when it has nothing to poll for (no type enabled and supported).
pub const IDLE: Duration = Duration::from_secs(60);
/// How often a running task's progress is sent, which is also how soon a cancel reaches it.
pub const PROGRESS_EVERY: Duration = Duration::from_secs(15);
/// How often recovery looks again at a task still running in its own unit.
pub const RECOVERY_CHECK: Duration = Duration::from_secs(5);

/// Reasons this module reports (P3-S02's codes).
pub mod reason {
    pub const UNKNOWN_TYPE: &str = "unknown_type";
    pub const NOT_ENABLED_LOCALLY: &str = "not_enabled_locally";
    pub const NOT_SUPPORTED: &str = "not_supported";
    pub const INVALID_PARAMS: &str = "invalid_params";
    pub const INTERRUPTED: &str = "interrupted";
    /// The agent holds the task but never ran it (P3-S05, #31).
    pub const NOT_RUN: &str = "not_run";
    pub const AGENT_ERROR: &str = "agent_error";
}

/// What recovering one task did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovery {
    /// Its outcome is recorded `finished`, ready to report.
    Recorded,
    /// Part of it still runs in its own unit; nothing was recorded.
    Running,
}

/// The [`Control`] of a running task: progress to the server, and the server's cancel (P3-S05).
struct Progress<'a> {
    api: &'a dyn TaskApi,
    id: &'a str,
    shutdown: &'a Shutdown,
    every: Duration,
    next: std::cell::Cell<Option<Instant>>,
    cancel: std::cell::Cell<bool>,
    ended: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
}

impl Control for Progress<'_> {
    fn shutdown(&self) -> &Shutdown {
        self.shutdown
    }

    fn cancel_requested(&self) -> bool {
        let now = Instant::now();
        if self.cancel.get() || self.next.get().is_some_and(|at| now < at) {
            return self.cancel.get();
        }
        self.next.set(Some(now + self.every));
        match self.api.progress(self.id, None) {
            Ok(reply) => {
                self.failed.set(false);
                if reply.cancel {
                    tracing::warn!(
                        task_id = self.id,
                        "the server asked to cancel the running task"
                    );
                    self.cancel.set(true);
                }
                if reply.state != "running" && !self.ended.replace(true) {
                    tracing::warn!(
                        task_id = self.id,
                        server_state = reply.state.as_str(),
                        "the server has already ended this task; its result will be kept as a late result"
                    );
                }
            }
            Err(error) => {
                if !self.failed.replace(true) {
                    tracing::warn!(
                        task_id = self.id,
                        status = error.status(),
                        "cannot send the running task's progress; the task goes on"
                    );
                }
            }
        }
        self.cancel.get()
    }
}

/// The heartbeat's "tasks are waiting" directive, raised by the heartbeat loop and taken by the poller.
#[derive(Debug, Default)]
pub struct TaskHint(AtomicBool);

impl TaskHint {
    pub fn raise(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether a hint was raised since the last call.
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

/// The poller's state across iterations of its loop.
pub struct Poller<'a, R: Rng> {
    state_dir: PathBuf,
    settings: &'a TaskSettings,
    executor: &'a dyn Executor,
    updater: Option<&'a Updater>,
    shutdown: &'a Shutdown,
    hint: &'a TaskHint,
    interval: Interval,
    ledger: Option<Ledger>,
    open_after: Option<Instant>,
    next_poll: Option<Instant>,
    /// When the last failed request may be retried.
    retry_after: Option<Instant>,
    backoff: Backoff<R>,
    notes: std::collections::HashSet<String>,
    /// The poll interval the server last asked for (`poll_seconds`), clamped.
    server_interval: Option<Duration>,
    progress_every: Duration,
}

impl<'a, R: Rng> Poller<'a, R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_dir: &Path,
        settings: &'a TaskSettings,
        executor: &'a dyn Executor,
        updater: Option<&'a Updater>,
        shutdown: &'a Shutdown,
        hint: &'a TaskHint,
        interval: Interval,
        backoff: Backoff<R>,
    ) -> Self {
        Self {
            state_dir: state_dir.to_owned(),
            settings,
            executor,
            updater,
            shutdown,
            hint,
            interval,
            ledger: None,
            open_after: None,
            next_poll: None,
            retry_after: None,
            backoff,
            notes: Default::default(),
            server_interval: None,
            progress_every: PROGRESS_EVERY,
        }
    }

    /// Sends progress this often while a task runs (tests).
    #[cfg(test)]
    pub fn set_progress_every(&mut self, every: Duration) {
        self.progress_every = every;
    }

    /// Whether this agent polls at all: some type is both enabled here and implemented.
    pub fn polls(&self) -> bool {
        self.settings
            .enabled()
            .iter()
            .any(|t| self.executor.implements(t))
    }

    /// The ledger, if open (tests).
    #[cfg(test)]
    pub fn ledger(&self) -> Option<&Ledger> {
        self.ledger.as_ref()
    }

    fn note(&mut self, note: &str) -> bool {
        self.notes.len() < 256 && self.notes.insert(note.to_owned())
    }

    /// One iteration: opens the ledger if needed, reports what is unreported, and polls if it is time.
    /// Returns how long to wait before the next iteration (at most [`HINT_CHECK`] while polling).
    pub fn tick(&mut self, api: &dyn TaskApi, now: Instant, wall: SystemTime) -> Duration {
        if self.ledger.is_none() && !self.open(now, wall) {
            return LEDGER_RETRY;
        }
        if let Some(after) = self.retry_after {
            if now < after {
                return (after - now).min(HINT_CHECK);
            }
            self.retry_after = None;
        }
        if let Err(wait) = self.reconcile(api, now, wall) {
            return wait;
        }
        if !self.polls() {
            // A hint means nothing to an agent that runs no type.
            self.hint.take();
            return IDLE;
        }
        let hinted = self.hint.take();
        let due = self.next_poll.is_none_or(|at| now >= at);
        if !due && !hinted {
            return self
                .next_poll
                .map_or(HINT_CHECK, |at| (at - now).min(HINT_CHECK));
        }
        self.poll_once(api, now, wall);
        HINT_CHECK.min(
            self.retry_after
                .or(self.next_poll)
                .map_or(HINT_CHECK, |at| at.saturating_duration_since(now)),
        )
    }

    fn interval(&self) -> Duration {
        self.server_interval.unwrap_or(self.interval.start)
    }

    /// Opens the ledger, logging what recovery found. `false` if it cannot be opened yet.
    fn open(&mut self, now: Instant, wall: SystemTime) -> bool {
        if self.open_after.is_some_and(|at| now < at) {
            return false;
        }
        match Ledger::open(&self.state_dir, wall) {
            Ok((ledger, recovery)) => {
                if recovery.torn_tail {
                    tracing::warn!(
                        "the task ledger ended in a partly written record (the agent stopped while writing it); it was dropped, and nothing it described had been acted on"
                    );
                }
                if let Some(why) = &recovery.damaged {
                    tracing::error!(
                        damaged_copy = %self.state_dir.join(ledger::DAMAGED_FILE).display(),
                        hold_until_unix = ledger.hold_until(wall).unwrap_or(0),
                        "the task ledger is damaged ({why}): the readable records are kept and no task will run until every task that existed before has expired on the server; tasks received meanwhile are reported, not run"
                    );
                }
                if recovery.unknown_records > 0 {
                    tracing::warn!(
                        records = recovery.unknown_records,
                        "the task ledger has records this agent version cannot read (written by a newer version); their tasks are reported, never run"
                    );
                }
                self.ledger = Some(ledger);
                self.open_after = None;
                true
            }
            Err(e) => {
                if self.note(&format!("open {e}")) {
                    let why = match &e {
                        LedgerError::Io(io) => {
                            crate::state::describe_write_error(&self.state_dir, io)
                        }
                        other => other.to_string(),
                    };
                    tracing::error!(
                        state_dir = %self.state_dir.display(),
                        "cannot open the task ledger ({why}); no task will be polled or run until it can be"
                    );
                }
                self.open_after = Some(now + LEDGER_RETRY);
                false
            }
        }
    }

    /// The ledger failed: forget it, so the next iteration reopens it and reads what is durable.
    fn drop_ledger(&mut self, now: Instant, error: &LedgerError) {
        tracing::error!("the task ledger cannot be written ({error}); it will be reopened");
        self.ledger = None;
        self.open_after = Some(now + LEDGER_RETRY);
    }

    fn failed(&mut self, now: Instant, error: &ApiError) -> Duration {
        let wait = self.backoff.on_failure(error);
        self.retry_after = Some(now + wait);
        wait.min(HINT_CHECK)
    }

    /// Reports every unreported task, oldest first. `Err` is how long to wait when one could not be.
    pub fn reconcile(
        &mut self,
        api: &dyn TaskApi,
        now: Instant,
        wall: SystemTime,
    ) -> Result<(), Duration> {
        let mut pending = match &self.ledger {
            Some(ledger) => ledger.pending(),
            None => return Err(LEDGER_RETRY),
        };
        // The task whose result is stored goes first, so recovering another never overwrites it.
        if let Some(owner) = self.ledger.as_ref().and_then(Ledger::result_owner) {
            pending.sort_by_key(|t| t.id != owner);
        }
        for task in pending {
            if !matches!(task.state, State::Finished { .. }) {
                let recovery = self.recover(&task, wall).map_err(|e| {
                    self.drop_ledger(now, &e);
                    LEDGER_RETRY
                })?;
                if recovery == Recovery::Running {
                    if self.note(&format!("running {}", task.id)) {
                        tracing::info!(
                            task_id = task.id.as_str(),
                            "a task the agent started before it stopped still runs in its own unit; waiting for it before polling for another"
                        );
                    }
                    return Err(RECOVERY_CHECK);
                }
            }
            self.report(api, &task.id, now, wall)?;
        }
        Ok(())
    }

    /// Records the outcome of a task the agent did not see to its end, from what the ledger says (and,
    /// for a task that ran, what the executor finds of it).
    fn recover(&mut self, task: &Task, wall: SystemTime) -> Result<Recovery, LedgerError> {
        let Some(ledger) = self.ledger.as_mut() else {
            return Err(LedgerError::Poisoned);
        };
        // A result stored before the crash is the real outcome: it finished, only `finished` is missing.
        if let Some(body) = ledger.result(&task.id) {
            let (outcome, reason) = wire::outcome_of(&body)
                .unwrap_or((Outcome::Failed, Some(reason::INTERRUPTED.to_owned())));
            tracing::warn!(
                task_id = task.id.as_str(),
                outcome = outcome.as_str(),
                "recovered a task that finished before the agent stopped; reporting its result"
            );
            ledger.finish(&task.id, outcome, reason.as_deref(), &body, wall)?;
            return Ok(Recovery::Recorded);
        }
        let (outcome, reason) = recovered_outcome(&task.state);
        let started_at = task.started_at.clone();
        if task.state == State::Started && task.executed {
            match self.executor.recover(task) {
                Recovered::Nothing => {}
                Recovered::Running => return Ok(Recovery::Running),
                Recovered::Ended(ran) => {
                    tracing::warn!(
                        task_id = task.id.as_str(),
                        outcome = ran.outcome.as_str(),
                        "a task that ran on in its own unit while the agent was stopped has ended; reporting what it did"
                    );
                    let body = wire::result_body(&wire::ResultFields {
                        outcome: ran.outcome,
                        reason: ran.reason,
                        exit_status: ran.exit_status,
                        started_at: Some(rfc3339(ran.started_at)),
                        finished_at: rfc3339(ran.finished_at),
                        output: ran.output,
                        output_truncated: ran.output_truncated,
                        details: ran.details,
                    });
                    let ledger = self.ledger.as_mut().ok_or(LedgerError::Poisoned)?;
                    ledger.finish(&task.id, ran.outcome, ran.reason, &body, wall)?;
                    return Ok(Recovery::Recorded);
                }
            }
        }
        let Some(ledger) = self.ledger.as_mut() else {
            return Err(LedgerError::Poisoned);
        };
        let body = wire::result_body(&wire::ResultFields {
            outcome,
            reason: Some(reason),
            exit_status: None,
            started_at: started_at.clone(),
            finished_at: rfc3339(wall),
            output: String::new(),
            output_truncated: false,
            details: serde_json::Map::new(),
        });
        tracing::warn!(
            task_id = task.id.as_str(),
            task_type = task.task_type.as_deref().unwrap_or(""),
            ledger_state = task.state.name(),
            executed = task.executed,
            outcome = outcome.as_str(),
            reason,
            "a task was left unfinished when the agent stopped; reporting it, not running it"
        );
        ledger.finish(&task.id, outcome, Some(reason), &body, wall)?;
        Ok(Recovery::Recorded)
    }

    /// Sends the stored result of `id` once. `Err` is how long to wait when it could not be sent.
    fn report(
        &mut self,
        api: &dyn TaskApi,
        id: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Result<(), Duration> {
        let Some(ledger) = self.ledger.as_ref() else {
            return Err(LEDGER_RETRY);
        };
        let body = match ledger.result(id) {
            Some(body) => body,
            None => {
                // The stored result is gone (or unreadable): rebuild it from the ledger once and store
                // it, so every retry sends the same body and `report_id`.
                let Some(body) = rebuilt(ledger, id) else {
                    return Ok(());
                };
                let ledger = self.ledger.as_mut().ok_or(LEDGER_RETRY)?;
                if let Err(e) = ledger.store_result(id, &body) {
                    self.drop_ledger(now, &e);
                    return Err(LEDGER_RETRY);
                }
                body
            }
        };
        match api.result(id, &body) {
            Ok(reply) => {
                self.backoff.on_success();
                let rejected = match &reply {
                    Reply::Accepted => {
                        tracing::info!(
                            task_id = id,
                            outcome = body["outcome"].as_str().unwrap_or(""),
                            "task result accepted by the server"
                        );
                        false
                    }
                    Reply::Rejected(code) => {
                        tracing::error!(
                            task_id = id,
                            code = code.as_str(),
                            "the server will not accept this task result; it is dropped (the ledger keeps the task, so it is never run again)"
                        );
                        true
                    }
                };
                let ledger = self.ledger.as_mut().ok_or(LEDGER_RETRY)?;
                if let Err(e) = ledger.reported(id, rejected, wall) {
                    self.drop_ledger(now, &e);
                    return Err(LEDGER_RETRY);
                }
                Ok(())
            }
            Err(error) => {
                if self.note(&format!("result {id} {}", error.status())) {
                    tracing::warn!(
                        task_id = id,
                        status = error.status(),
                        "cannot send the task result yet; it will be sent again"
                    );
                }
                Err(self.failed(now, &error))
            }
        }
    }

    /// Polls once and handles the task it delivers, if any.
    fn poll_once(&mut self, api: &dyn TaskApi, now: Instant, wall: SystemTime) {
        let slot = match self.updater.map(Updater::task_slot) {
            Some(Err(why)) => {
                if self.note(&format!("slot {why}")) {
                    tracing::info!("not polling for tasks: {why}");
                }
                self.next_poll = Some(now + self.interval());
                return;
            }
            Some(Ok(slot)) => Some(slot),
            None => None,
        };
        self.notes.retain(|n| !n.starts_with("slot "));
        let reply = match api.poll() {
            Ok(reply) => reply,
            Err(error) => {
                if self.note(&format!("poll {}", error.status())) {
                    tracing::warn!(
                        status = error.status(),
                        "cannot poll for tasks; trying again later"
                    );
                }
                self.failed(now, &error);
                return;
            }
        };
        self.backoff.on_success();
        self.notes.retain(|n| !n.starts_with("poll "));
        if let Some(seconds) = reply.poll_seconds {
            let wanted = self.interval.clamp_server_value(seconds);
            if self.server_interval != Some(wanted) {
                tracing::info!(
                    seconds = wanted.as_secs(),
                    "polling for tasks at the interval the server asks for"
                );
                self.server_interval = Some(wanted);
            }
        }
        if let Some(id) = &reply.cancel {
            // The poller polls only between tasks, so nothing is running here to stop.
            if self.note(&format!("cancel {id}")) {
                tracing::info!(
                    task_id = id.as_str(),
                    "the server asked to cancel a task that is not running here; nothing to stop"
                );
            }
        }
        match reply.task {
            None => self.next_poll = Some(now + self.interval()),
            Some(task) => {
                // One at a time: after a new task, poll again straight away, in case another is waiting.
                // A delivery this agent will not take (an id it already has, or one it cannot record)
                // waits the interval, so a server that keeps sending it is not polled in a loop.
                self.next_poll = Some(if self.handle(api, &task, now, wall) {
                    now
                } else {
                    now + self.interval()
                });
            }
        }
        drop(slot);
    }

    /// Takes one delivered task through the steps in the module documentation. `false` when it was
    /// not taken: an id already in the ledger, or a delivery that cannot be recorded.
    fn handle(
        &mut self,
        api: &dyn TaskApi,
        task: &Delivered,
        now: Instant,
        wall: SystemTime,
    ) -> bool {
        let Some(ledger) = self.ledger.as_mut() else {
            return false;
        };
        let oversize = serde_json::to_vec(&task.parameters)
            .map_or(true, |b| b.len() > ledger::MAX_PARAMETERS_BYTES);
        let recorded = if oversize {
            &Value::Null
        } else {
            &task.parameters
        };
        let receipt = ledger.receive(
            &task.id,
            &task.task_type,
            task.catalog_version,
            task.timeout_seconds,
            recorded,
            wall,
        );
        match receipt {
            Ok(Receipt::New) => {}
            Ok(Receipt::Known(state)) => {
                let executed = ledger.task(&task.id).is_none_or(|t| t.executed);
                if self.note(&format!("known {}", task.id)) {
                    tracing::warn!(
                        task_id = task.id.as_str(),
                        task_type = crate::logging::sanitize(&task.task_type, 64).as_str(),
                        ledger_state = state.name(),
                        "the server delivered a task this agent already has in its ledger; it is not run again"
                    );
                }
                if state == State::Reported {
                    self.close_known(api, &task.id, executed, now, wall);
                }
                return false;
            }
            Err(LedgerError::Invalid(why)) => {
                if self.note(&format!("invalid {why}")) {
                    tracing::error!("ignoring a delivered task that cannot be recorded: {why}");
                }
                return false;
            }
            Err(e) => {
                self.drop_ledger(now, &e);
                return false;
            }
        }
        tracing::info!(
            task_id = task.id.as_str(),
            task_type = crate::logging::sanitize(&task.task_type, 64).as_str(),
            timeout_seconds = task.timeout_seconds,
            "task received"
        );
        #[cfg(test)]
        if tests::crash_at(tests::Point::Received) {
            return true;
        }
        let refusal = if oversize {
            Some((Outcome::Refused, reason::INVALID_PARAMS))
        } else {
            self.refusal(task, wall)
        };
        if let Some((outcome, why)) = refusal {
            tracing::warn!(
                task_id = task.id.as_str(),
                task_type = crate::logging::sanitize(&task.task_type, 64).as_str(),
                outcome = outcome.as_str(),
                reason = why,
                "task not run: nothing was started"
            );
            let body = wire::result_body(&wire::ResultFields {
                outcome,
                reason: Some(why),
                exit_status: None,
                started_at: None,
                finished_at: rfc3339(wall),
                output: String::new(),
                output_truncated: false,
                details: serde_json::Map::new(),
            });
            self.finish(&task.id, outcome, Some(why), &body, now, wall);
        } else {
            self.execute(api, task, now, wall);
        }
        #[cfg(test)]
        if tests::crash_at(tests::Point::Finished) {
            return true;
        }
        let _ = self.report(api, &task.id, now, wall);
        true
    }

    /// Why this agent will not run `task`, if it will not, as the outcome and reason to report;
    /// checked with nothing run. Every reason is `refused` except a ledger hold: the ledger lost
    /// records, so this may be a task that ran before, which the contract reports `failed` with
    /// `agent_error` ("ran, or may have run").
    pub fn refusal(&self, task: &Delivered, wall: SystemTime) -> Option<(Outcome, &'static str)> {
        if self.ledger.as_ref().is_some_and(|l| l.held(wall)) {
            return Some((Outcome::Failed, reason::AGENT_ERROR));
        }
        let refused = |why| Some((Outcome::Refused, why));
        let Some(entry) = Catalog::embedded()
            .ok()
            .and_then(|c| c.get(&task.task_type))
        else {
            return refused(reason::UNKNOWN_TYPE);
        };
        if !self.settings.is_enabled(&entry.id) {
            return refused(reason::NOT_ENABLED_LOCALLY);
        }
        if !self.executor.implements(&entry.id) {
            return refused(reason::NOT_SUPPORTED);
        }
        self.executor.check(task).err().and_then(refused)
    }

    /// Records `finished`, dropping the ledger if it cannot be written.
    fn finish(
        &mut self,
        id: &str,
        outcome: Outcome,
        reason: Option<&str>,
        body: &Value,
        now: Instant,
        wall: SystemTime,
    ) {
        let written = match self.ledger.as_mut() {
            Some(ledger) => ledger.finish(id, outcome, reason, body, wall),
            None => return,
        };
        match written {
            Ok(()) => tracing::info!(
                task_id = id,
                outcome = outcome.as_str(),
                reason = reason.unwrap_or(""),
                "task finished"
            ),
            Err(e) => self.drop_ledger(now, &e),
        }
    }

    /// Closes a task the server delivered again although the ledger has it reported (or dropped): the
    /// server holds it as claimed, and would deliver it until it expired. `failed` is the result a
    /// claimed task accepts; nothing is run and nothing is written to the ledger.
    fn close_known(
        &mut self,
        api: &dyn TaskApi,
        id: &str,
        executed: bool,
        now: Instant,
        wall: SystemTime,
    ) {
        let reason = if executed {
            reason::AGENT_ERROR
        } else {
            reason::NOT_RUN
        };
        let body = wire::result_body(&wire::ResultFields {
            outcome: Outcome::Failed,
            reason: Some(reason),
            exit_status: None,
            started_at: None,
            finished_at: rfc3339(wall),
            output: String::new(),
            output_truncated: false,
            details: serde_json::Map::new(),
        });
        match api.result(id, &body) {
            Ok(Reply::Accepted) => {
                self.backoff.on_success();
                tracing::warn!(
                    task_id = id,
                    reason,
                    "closed a task the server delivered again: reported failed, not run"
                );
            }
            Ok(Reply::Rejected(code)) => tracing::warn!(
                task_id = id,
                code = code.as_str(),
                "the server refused to close a task it delivered again; it is still not run"
            ),
            Err(error) => {
                tracing::warn!(
                    task_id = id,
                    status = error.status(),
                    "cannot close a task the server delivered again; trying when it is delivered next"
                );
                self.failed(now, &error);
            }
        }
    }

    /// A task the server would not let run: recorded as not run and as answered, so nothing is sent.
    fn drop_unrun(&mut self, id: &str, now: Instant, wall: SystemTime) {
        let Some(ledger) = self.ledger.as_mut() else {
            return;
        };
        let body = wire::result_body(&wire::ResultFields {
            outcome: Outcome::Cancelled,
            reason: None,
            exit_status: None,
            started_at: None,
            finished_at: rfc3339(wall),
            output: String::new(),
            output_truncated: false,
            details: serde_json::Map::new(),
        });
        let written = ledger
            .finish(id, Outcome::Cancelled, Some("not_run"), &body, wall)
            .and_then(|()| ledger.reported(id, true, wall));
        if let Err(e) = written {
            self.drop_ledger(now, &e);
        }
    }

    /// Steps 4 to 6: `started`, the server's acceptance of `start`, and the run.
    fn execute(&mut self, api: &dyn TaskApi, task: &Delivered, now: Instant, wall: SystemTime) {
        let Some(ledger) = self.ledger.as_mut() else {
            return;
        };
        if let Err(e) = ledger.start(&task.id, wall) {
            return self.drop_ledger(now, &e);
        }
        let started_at = rfc3339(wall);
        tracing::info!(task_id = task.id.as_str(), "task recorded as started");
        #[cfg(test)]
        if tests::crash_at(tests::Point::Started) {
            return;
        }
        // Only the server's acceptance lets the task run. Retried until accepted, refused, or the
        // agent stops (then recovery reports it).
        loop {
            match api.start(&task.id, &started_at) {
                Ok(Reply::Accepted) => break,
                Ok(Reply::Rejected(state)) => {
                    // `run: false` (for example cancelled before it started), or the task is gone:
                    // record that it did not run and drop it, with no result to send (P3-S03).
                    if state == "queued" {
                        // The claim lapsed before `start` arrived (P3-S05, threat model L2). It is
                        // this host's to close: `failed`/`not_run`, reported by the caller.
                        tracing::warn!(
                            task_id = task.id.as_str(),
                            "the server put the task back in its queue before it could start; nothing was run, and it is reported failed (not_run)"
                        );
                        let body = wire::result_body(&wire::ResultFields {
                            outcome: Outcome::Failed,
                            reason: Some(reason::NOT_RUN),
                            exit_status: None,
                            started_at: None,
                            finished_at: rfc3339(wall),
                            output: String::new(),
                            output_truncated: false,
                            details: serde_json::Map::new(),
                        });
                        return self.finish(
                            &task.id,
                            Outcome::Failed,
                            Some(reason::NOT_RUN),
                            &body,
                            now,
                            wall,
                        );
                    } else {
                        tracing::warn!(
                            task_id = task.id.as_str(),
                            server_state = state.as_str(),
                            "the server did not let the task run (it may have been cancelled); nothing was run"
                        );
                    }
                    return self.drop_unrun(&task.id, now, wall);
                }
                Err(error) => {
                    let wait = self.backoff.on_failure(&error);
                    tracing::warn!(
                        task_id = task.id.as_str(),
                        status = error.status(),
                        "cannot tell the server the task started; it does not run until the server accepts"
                    );
                    // A refusal that only an operator or an upgrade can fix (401, 403, 426): give up
                    // on this task rather than hold the task slot, which would also hold back the
                    // agent update that a 426 needs (review of #166). It stays `started` without
                    // `finished`, so recovery reports it `interrupted`, and it never runs.
                    if RetryClass::of(&error) == RetryClass::Long {
                        tracing::warn!(
                            task_id = task.id.as_str(),
                            "giving up on starting the task; it is reported, not run"
                        );
                        self.retry_after = Some(now + wait);
                        return;
                    }
                    if self.shutdown.wait(wait) {
                        return;
                    }
                }
            }
        }
        self.backoff.on_success();
        #[cfg(test)]
        if tests::crash_at(tests::Point::Acknowledged) {
            return;
        }
        let Some(ledger) = self.ledger.as_mut() else {
            return;
        };
        if let Err(e) = ledger.executing(&task.id, SystemTime::now()) {
            // Not recorded, so not run: it stays `started`, and recovery reports it.
            return self.drop_ledger(now, &e);
        }
        tracing::info!(task_id = task.id.as_str(), "task running");
        let control = Progress {
            api,
            id: &task.id,
            shutdown: self.shutdown,
            every: self.progress_every,
            next: Default::default(),
            cancel: Default::default(),
            ended: Default::default(),
            failed: Default::default(),
        };
        let Some(ran) = self.executor.run(task, &control) else {
            tracing::warn!(
                task_id = task.id.as_str(),
                "the agent is stopping while the task runs on in its own unit; it stays recorded as started, and its outcome is reported when the agent starts again"
            );
            return;
        };
        #[cfg(test)]
        if tests::crash_at(tests::Point::Ran) {
            return;
        }
        let body = wire::result_body(&wire::ResultFields {
            outcome: ran.outcome,
            reason: ran.reason,
            exit_status: ran.exit_status,
            started_at: Some(rfc3339(ran.started_at)),
            finished_at: rfc3339(ran.finished_at),
            output: ran.output,
            output_truncated: ran.output_truncated,
            details: ran.details,
        });
        self.finish(
            &task.id,
            ran.outcome,
            ran.reason,
            &body,
            now,
            SystemTime::now(),
        );
    }
}

/// The outcome recovery reports for a task in `state` with no stored result.
pub fn recovered_outcome(state: &State) -> (Outcome, &'static str) {
    match state {
        // Recorded but never started: nothing ran, and `start` was never sent, so the server holds it
        // claimed and accepts `not_run`. Never run now either (it is in the ledger).
        State::Received => (Outcome::Failed, reason::NOT_RUN),
        // `start` was sent: the server may have it running, so `interrupted`, which it accepts then.
        State::Started => (Outcome::Failed, reason::INTERRUPTED),
        State::Unknown | State::Finished { .. } | State::Reported => {
            (Outcome::Failed, reason::AGENT_ERROR)
        }
    }
}

/// A result rebuilt from the ledger alone, when the stored result is missing.
fn rebuilt(ledger: &Ledger, id: &str) -> Option<Value> {
    let task = ledger.task(id)?;
    let State::Finished { outcome, reason } = &task.state else {
        return None;
    };
    Some(wire::result_body(&wire::ResultFields {
        outcome: *outcome,
        reason: reason.as_deref(),
        exit_status: None,
        started_at: task.started_at.clone(),
        finished_at: rfc3339(SystemTime::now()),
        output: String::new(),
        output_truncated: false,
        details: serde_json::Map::new(),
    }))
}

#[cfg(test)]
pub(crate) mod tests;
