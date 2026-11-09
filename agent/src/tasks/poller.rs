//! The task poller (FR-3.2, FR-3.3, AC-3.3, P3-A02): polls the server for a task, records it in the
//! [`Ledger`], refuses what this agent will not run, and reports every result until it is accepted.
//!
//! **When it polls.** Only when the owner enabled a type that this agent implements ([`Poller::polls`]):
//! with nothing enabled and supported the server offers this host nothing (P3-A01), so there is nothing
//! to ask for. Then every poll interval (`[task_poll]` in the config, 30 s by default, the server's
//! hint clamped to its bounds), and within [`HINT_CHECK`] of a heartbeat that says tasks are
//! waiting ([`TaskHint`]). After a failure it backs off as every other request does ([`Backoff`],
//! P1-A02). One task at a time: a task is handled to its end before the next poll.
//!
//! **What it does with a task.** In this order, stopping at the first that fails:
//!
//! 1. The id is not already in the ledger. A known id is never run again (duplicate delivery); if it
//!    is not reported yet, step 7 reports it.
//! 2. `received` is recorded.
//! 3. The local checks ([`Poller::refusal`]): no ledger hold, the type is in the embedded catalog
//!    (`unknown_type`), enabled here (`not_enabled_locally`), implemented (`not_supported`), and the
//!    executor's own checks ([`Executor::check`]). A refusal is recorded `finished` and reported;
//!    nothing is started.
//! 4. `started` is recorded and flushed.
//! 5. `start` is sent; the task runs only once the server accepts it (P3-S03). A refused `start` (the
//!    task was cancelled) is recorded and nothing runs.
//! 6. The executor runs it ([`Executor::run`]), and the result is recorded `finished`.
//! 7. The result is sent until the server accepts it (or refuses it for good), then `reported`.
//!
//! In this build there is no executor ([`super::executor::NoExecutor`], P3-A03): no type is
//! implemented, so the poller does not poll at all by default, and any task that does arrive stops at
//! step 3 with `not_supported`. Steps 4 to 6 are exercised by the tests with a fake executor.
//!
//! **Recovery.** On start, and whenever the ledger is reopened, every unreported task is reported
//! before anything is polled ([`Poller::reconcile`]):
//!
//! - `received` only: it never started, so nothing ran. Reported `failed`, `not_run`... see
//!   [`recovered_outcome`];
//! - `started` without `finished`: it may have run. Reported `failed` with reason `interrupted`, unless
//!   the stored result shows it finished, which is then sent as it was;
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
use super::executor::{Delivered, Executor};
use super::ledger::{self, Ledger, LedgerError, Outcome, Receipt, State, Task};
use super::settings::TaskSettings;
use super::wire::{self, Reply, TaskApi};
use crate::client::ApiError;
use crate::config::Interval;
use crate::report::rfc3339;
use crate::retry::{Backoff, Rng};
use crate::shutdown::Shutdown;
use crate::update::Updater;

/// How often the poller looks for a hint the heartbeat loop raised.
pub const HINT_CHECK: Duration = Duration::from_secs(5);
/// How long to wait before opening a ledger that could not be opened.
pub const LEDGER_RETRY: Duration = Duration::from_secs(60);
/// How long the poller sleeps when it has nothing to poll for (no type enabled and supported).
pub const IDLE: Duration = Duration::from_secs(60);

/// Reasons this module reports (P3-S02's codes).
pub mod reason {
    pub const UNKNOWN_TYPE: &str = "unknown_type";
    pub const NOT_ENABLED_LOCALLY: &str = "not_enabled_locally";
    pub const NOT_SUPPORTED: &str = "not_supported";
    pub const INVALID_PARAMS: &str = "invalid_params";
    pub const INTERRUPTED: &str = "interrupted";
    pub const AGENT_ERROR: &str = "agent_error";
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
    /// The interval the server last asked for, clamped.
    server_interval: Option<Duration>,
    ledger: Option<Ledger>,
    open_after: Option<Instant>,
    next_poll: Option<Instant>,
    /// When the last failed request may be retried.
    retry_after: Option<Instant>,
    backoff: Backoff<R>,
    notes: std::collections::HashSet<String>,
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
            server_interval: None,
            ledger: None,
            open_after: None,
            next_poll: None,
            retry_after: None,
            backoff,
            notes: Default::default(),
        }
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
        let pending = match &self.ledger {
            Some(ledger) => ledger.pending(),
            None => return Err(LEDGER_RETRY),
        };
        for task in pending {
            if !matches!(task.state, State::Finished { .. }) {
                self.recover(&task, wall).map_err(|e| {
                    self.drop_ledger(now, &e);
                    LEDGER_RETRY
                })?;
            }
            self.report(api, &task.id, now, wall)?;
        }
        Ok(())
    }

    /// Records the outcome of a task the agent did not see to its end, from what the ledger says.
    fn recover(&mut self, task: &Task, wall: SystemTime) -> Result<(), LedgerError> {
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
            return ledger.finish(&task.id, outcome, reason.as_deref(), &body, wall);
        }
        let (outcome, reason) = recovered_outcome(&task.state);
        let started_at = task.started_at.clone();
        let body = wire::result_body(&wire::ResultFields {
            outcome,
            reason: Some(reason),
            exit_status: None,
            started_at: started_at.clone(),
            finished_at: Some(rfc3339(wall)),
            output: String::new(),
            output_truncated: false,
            details: serde_json::Map::new(),
        });
        tracing::warn!(
            task_id = task.id.as_str(),
            task_type = task.task_type.as_deref().unwrap_or(""),
            ledger_state = task.state.name(),
            outcome = outcome.as_str(),
            reason,
            "a task was left unfinished when the agent stopped; reporting it, not running it"
        );
        ledger.finish(&task.id, outcome, Some(reason), &body, wall)
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
        let Some(body) = ledger.result(id).or_else(|| rebuilt(ledger, id)) else {
            return Ok(());
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
        if let Some(seconds) = reply.poll_after_seconds {
            self.server_interval = Some(self.interval.clamp_server_value(seconds));
        }
        match reply.task {
            None => self.next_poll = Some(now + self.interval()),
            Some(task) => {
                self.handle(api, &task, now, wall);
                // One at a time: poll again straight away, in case another is waiting.
                self.next_poll = Some(now);
            }
        }
        drop(slot);
    }

    /// Takes one delivered task through the steps in the module documentation.
    fn handle(&mut self, api: &dyn TaskApi, task: &Delivered, now: Instant, wall: SystemTime) {
        let Some(ledger) = self.ledger.as_mut() else {
            return;
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
            task.deadline.as_deref(),
            recorded,
            wall,
        );
        match receipt {
            Ok(Receipt::New) => {}
            Ok(Receipt::Known(state)) => {
                if self.note(&format!("known {}", task.id)) {
                    tracing::warn!(
                        task_id = task.id.as_str(),
                        task_type = crate::logging::sanitize(&task.task_type, 64).as_str(),
                        ledger_state = state.name(),
                        "the server delivered a task this agent already has in its ledger; it is not run again"
                    );
                }
                return;
            }
            Err(LedgerError::Invalid(why)) => {
                if self.note(&format!("invalid {why}")) {
                    tracing::error!("ignoring a delivered task that cannot be recorded: {why}");
                }
                return;
            }
            Err(e) => return self.drop_ledger(now, &e),
        }
        tracing::info!(
            task_id = task.id.as_str(),
            task_type = crate::logging::sanitize(&task.task_type, 64).as_str(),
            deadline = task.deadline.as_deref().unwrap_or(""),
            "task received"
        );
        #[cfg(test)]
        if tests::crash_at(tests::Point::Received) {
            return;
        }
        let refusal = if oversize {
            Some(reason::INVALID_PARAMS)
        } else {
            self.refusal(task, wall)
        };
        if let Some(why) = refusal {
            tracing::warn!(
                task_id = task.id.as_str(),
                task_type = crate::logging::sanitize(&task.task_type, 64).as_str(),
                reason = why,
                "task refused; nothing was run"
            );
            let body = wire::result_body(&wire::ResultFields {
                outcome: Outcome::Refused,
                reason: Some(why),
                exit_status: None,
                started_at: None,
                finished_at: Some(rfc3339(wall)),
                output: String::new(),
                output_truncated: false,
                details: serde_json::Map::new(),
            });
            self.finish(&task.id, Outcome::Refused, Some(why), &body, now, wall);
        } else {
            self.execute(api, task, now, wall);
        }
        #[cfg(test)]
        if tests::crash_at(tests::Point::Finished) {
            return;
        }
        let _ = self.report(api, &task.id, now, wall);
    }

    /// Why this agent will not run `task`, if it will not; checked with nothing run.
    pub fn refusal(&self, task: &Delivered, wall: SystemTime) -> Option<&'static str> {
        if self.ledger.as_ref().is_some_and(|l| l.held(wall)) {
            // The ledger lost records, so this could be a task that ran before.
            return Some(reason::AGENT_ERROR);
        }
        let Some(entry) = Catalog::embedded()
            .ok()
            .and_then(|c| c.get(&task.task_type))
        else {
            return Some(reason::UNKNOWN_TYPE);
        };
        if !self.settings.is_enabled(&entry.id) {
            return Some(reason::NOT_ENABLED_LOCALLY);
        }
        if !self.executor.implements(&entry.id) {
            return Some(reason::NOT_SUPPORTED);
        }
        self.executor.check(task).err()
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

    /// Steps 4 to 6: `started`, the server's acceptance of `start`, and the run.
    fn execute(&mut self, api: &dyn TaskApi, task: &Delivered, now: Instant, wall: SystemTime) {
        let Some(ledger) = self.ledger.as_mut() else {
            return;
        };
        if let Err(e) = ledger.start(&task.id, wall) {
            return self.drop_ledger(now, &e);
        }
        tracing::info!(task_id = task.id.as_str(), "task recorded as started");
        #[cfg(test)]
        if tests::crash_at(tests::Point::Started) {
            return;
        }
        // Only the server's acceptance lets the task run. Retried until accepted, refused, or the
        // agent stops (then recovery reports it).
        loop {
            match api.start(&task.id) {
                Ok(Reply::Accepted) => break,
                Ok(Reply::Rejected(code)) => {
                    tracing::warn!(
                        task_id = task.id.as_str(),
                        code = code.as_str(),
                        "the server refused to start the task (it may have been cancelled); nothing was run"
                    );
                    let body = wire::result_body(&wire::ResultFields {
                        outcome: Outcome::Cancelled,
                        reason: None,
                        exit_status: None,
                        started_at: None,
                        finished_at: Some(rfc3339(SystemTime::now())),
                        output: String::new(),
                        output_truncated: false,
                        details: serde_json::Map::new(),
                    });
                    self.finish(&task.id, Outcome::Cancelled, None, &body, now, wall);
                    return;
                }
                Err(error) => {
                    let wait = self.backoff.on_failure(&error);
                    tracing::warn!(
                        task_id = task.id.as_str(),
                        status = error.status(),
                        "cannot tell the server the task started; it does not run until the server accepts"
                    );
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
        tracing::info!(task_id = task.id.as_str(), "task running");
        let ran = self.executor.run(task, self.shutdown);
        #[cfg(test)]
        if tests::crash_at(tests::Point::Ran) {
            return;
        }
        let body = wire::result_body(&wire::ResultFields {
            outcome: ran.outcome,
            reason: ran.reason,
            exit_status: ran.exit_status,
            started_at: Some(rfc3339(ran.started_at)),
            finished_at: Some(rfc3339(ran.finished_at)),
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
        // Recorded but never started: nothing ran. Still never run now (it is in the ledger), so it is
        // reported as interrupted, which is what it was.
        State::Received | State::Started => (Outcome::Failed, reason::INTERRUPTED),
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
        finished_at: None,
        output: String::new(),
        output_truncated: false,
        details: serde_json::Map::new(),
    }))
}

#[cfg(test)]
pub(crate) mod tests;
