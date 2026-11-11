//! The task executor (P3-A03, P3-A05): the fixed registry of task implementations, strict parameter
//! checks, and the one way a task runs a program.
//!
//! The poller ([`super::poller`]) owns the ledger and the server conversation; the [`Executor`] owns
//! what a task type does. The poller asks it these things, and nothing else:
//!
//! 1. [`Executor::implements`]: whether this agent version has the type at all. A type it lacks is
//!    refused `not_supported`.
//! 2. [`Executor::check`]: the type's strict checks, with nothing run: typed parameters with
//!    `deny_unknown_fields` and explicit range and pattern checks ([`parse`], `invalid_params`), the
//!    local service allowlist (`not_allowed_locally`), a protected unit (`protected_service`).
//! 3. [`Executor::run`]: only after the `started` record is on disk, the server accepted `start`, and
//!    the `executing` record is on disk.
//! 4. [`Executor::recover`]: on start-up, for a task the ledger shows as started but not finished:
//!    whether part of it is still running outside the agent (a transient unit, threat model L8).
//!
//! The checks the poller makes itself, before any of these, are the ones that need no type: the type is
//! in the embedded catalog (`unknown_type`) and the owner enabled it here (`not_enabled_locally`).
//!
//! **The registry** ([`Registry`]) maps a catalog type id to a [`TaskImpl`]. It is fixed at build
//! time; nothing the server sends adds to it. A task implementation turns parameters into a [`Job`]
//! (or a refusal), and the job runs [`Program`]s through [`Run::program`], which is the only way a
//! task can start a process ([`spawn`]): absolute path, fixed arguments, at most one validated operand
//! after `--`, no shell, a fixed environment, its own process group, a deadline, bounded output.
//!
//! **Privilege** (P3-A05, `docs/operations/agent-task-privileges.md`). Every [`Program`] declares the
//! privilege it needs, and runs only for a type whose catalog `privilege` is at least that. A
//! `read_only` or `service_manager` program runs as a child of the agent, inside the agent's own
//! sandbox (`systemctl restart` reaches systemd over the local socket the unit already allows). A
//! `package_manager` program runs in a transient systemd unit outside the sandbox, with fixed
//! properties ([`unit`]).
//!
//! **Timeouts.** The deadline is the lower of the server's `timeout_seconds` and the catalog's,
//! measured from the start of the run on the monotonic clock (C6). At the deadline the whole group is
//! ended (`SIGTERM`, grace, `SIGKILL`) and the task reports `timed_out`.
//!
//! **Cancel and shutdown.** While a task runs, the poller's [`Control`] sends progress and says whether
//! the server asked to cancel it. An interruptible type is stopped and reports `cancelled`; a type that
//! cannot be interrupted is never stopped by a cancel (DEC-14). When the agent stops, an interruptible
//! task is stopped and reports `failed`/`interrupted`; a direct child that cannot be interrupted gets
//! [`spawn::SHUTDOWN_WAIT`] to finish first; a transient unit that cannot be interrupted is left
//! running, [`Executor::run`] returns `None`, the ledger keeps the task `started`, and the next start
//! waits for the unit and reports it ([`Executor::recover`]).
//!
//! The registered types are [`super::IMPLEMENTED`]: `apply_package_updates` (P3-AGENT-UPDATES, #37,
//! [`super::apply_updates`]); any other type is refused `not_supported` before anything is started.
//! The framework's own tests use test-only types.

pub mod output;
pub mod spawn;
pub mod unit;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::catalog::{Catalog, Privilege};
use super::ledger::{self, Outcome};
use super::settings::TaskSettings;
use crate::shutdown::Shutdown;
use output::Capture;
pub use spawn::{Exit, Program};

/// A task as the poll delivered it: only what the API carries (P3-S03), never a command.
#[derive(Debug, Clone, PartialEq)]
pub struct Delivered {
    /// The task's UUID.
    pub id: String,
    /// The catalog type id.
    pub task_type: String,
    /// Parameters, still to be checked by the type's typed struct ([`Executor::check`]).
    pub parameters: Value,
    /// The server's deadline: the task must finish within this many seconds of starting. The
    /// executor uses the lower of this and the catalog's `timeout_seconds` (P3-A03).
    pub timeout_seconds: u64,
    /// The catalog version the server built the task against.
    pub catalog_version: u32,
}

/// What running a task produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Execution {
    pub outcome: Outcome,
    /// A reason code for `failed`, `timed_out`, or `refused` (P3-S02's list).
    pub reason: Option<&'static str>,
    pub exit_status: Option<i32>,
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
    /// Captured output, already bounded and marked by the executor (P3-A03).
    pub output: String,
    pub output_truncated: bool,
    /// Structured details such as `reboot_required`.
    pub details: Map<String, Value>,
}

/// What the poller gives a running task: the agent's shutdown flag, and the server's cancel.
pub trait Control {
    fn shutdown(&self) -> &Shutdown;

    /// Called often while a task runs. Sends progress to the server now and then (P3-S03) and says
    /// whether the server has asked to cancel this task (P3-S05). Cheap between progress reports.
    fn cancel_requested(&self) -> bool;
}

/// What [`Executor::recover`] found of a task the agent did not see to its end.
#[derive(Debug, Clone, PartialEq)]
pub enum Recovered {
    /// Nothing of it is running or left to collect: the poller reports it `interrupted`.
    Nothing,
    /// Part of it still runs outside the agent; ask again later and run nothing meanwhile.
    Running,
    /// It ran to an end without the agent; this is what it did.
    Ended(Execution),
}

/// Runs task types (P3-A03's registry).
pub trait Executor: Send + Sync {
    /// Whether this agent version has an implementation of `task_type`.
    fn implements(&self, task_type: &str) -> bool;

    /// The type's own checks, with nothing run. `Err` is the refusal reason code.
    fn check(&self, task: &Delivered) -> Result<(), &'static str>;

    /// Runs the task. Called once per task id, ever, after `started` is durable and the server
    /// accepted `start`. Returns when the task ends, or when the agent stops: then with what it
    /// knows, or `None` if the task was left running outside the agent (see the module docs).
    fn run(&self, task: &Delivered, control: &dyn Control) -> Option<Execution>;

    /// What is left of a task that was started and not finished when the agent stopped.
    fn recover(&self, _task: &ledger::Task) -> Recovered {
        Recovered::Nothing
    }
}

/// How a job ended when it was not stopped.
#[derive(Debug, Clone, PartialEq)]
pub struct Finish {
    /// `succeeded` or `failed`.
    pub outcome: Outcome,
    /// For `failed`: `nonzero_exit`, `lock_timeout`, `agent_error`.
    pub reason: Option<&'static str>,
    pub exit_status: Option<i32>,
    pub details: Map<String, Value>,
}

impl Finish {
    /// `succeeded` for exit status 0, otherwise `failed` with `nonzero_exit`.
    pub fn from_exit(exit: Exit) -> Self {
        Self {
            outcome: if exit.success() {
                Outcome::Succeeded
            } else {
                Outcome::Failed
            },
            reason: (!exit.success()).then_some("nonzero_exit"),
            exit_status: exit.code,
            details: Map::new(),
        }
    }
}

/// Why a job stopped before its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The deadline passed; the program's group was ended.
    TimedOut,
    /// The server cancelled an interruptible task; it was stopped.
    Cancelled,
    /// The agent is stopping; the task was stopped (or gave up waiting for one that cannot be).
    Interrupted,
    /// The agent is stopping; a task that cannot be interrupted was left running in its unit.
    Detached,
    /// Something went wrong in the agent, with the reason to report (`agent_error`).
    Failed(&'static str),
}

/// What one task type does. Implementations are written in the agent's code and listed in the
/// registry; there is no other way to add one.
pub trait TaskImpl: Send + Sync {
    /// The catalog type id.
    fn type_id(&self) -> &'static str;

    /// Checks `parameters` strictly ([`parse`]) and anything else the type needs (`settings`, for the
    /// local allowlist), with nothing run, and returns the job to run, or the refusal reason.
    fn prepare(
        &self,
        parameters: &Value,
        settings: &TaskSettings,
    ) -> Result<Box<dyn Job>, &'static str>;

    /// How the task ended, decided from its transient units after the agent restarted while they ran
    /// (threat model L8): `steps` are the units found, as (step number, exit), in step order, and
    /// `output` is their output. Lines pushed to `notes` are added to the output. `None` keeps the
    /// framework's reading, which knows nothing of the job: `timed_out` if a unit reached its limit,
    /// `nonzero_exit` if one failed, otherwise `interrupted` (the job never saw its programs end).
    fn recovered(
        &self,
        _steps: &[(u32, Exit)],
        _timed_out: bool,
        _output: &str,
        _notes: &mut Vec<String>,
    ) -> Option<Finish> {
        None
    }
}

/// A prepared task, ready to run.
pub trait Job: Send {
    fn run(&self, run: &mut Run<'_>) -> Result<Finish, Stop>;
}

/// Parses task parameters into a typed struct (which should use `deny_unknown_fields`). Any
/// mismatch is `invalid_params`; range and pattern checks follow in the caller.
pub fn parse<T: DeserializeOwned>(parameters: &Value) -> Result<T, &'static str> {
    if !parameters.is_object() {
        return Err("invalid_params");
    }
    serde_json::from_value(parameters.clone()).map_err(|_| "invalid_params")
}

/// A running task's context: the only way it can start a process.
pub struct Run<'a> {
    task_id: &'a str,
    privilege: Privilege,
    limits: spawn::Limits,
    control: &'a dyn Control,
    units: &'a dyn unit::Units,
    capture: Arc<Mutex<Capture>>,
    steps: u32,
}

impl Run<'_> {
    /// Runs `program` to its end, adding its output to the task's. `Err` stops the job: return it.
    pub fn program(&mut self, program: &Program) -> Result<Exit, Stop> {
        if rank(program.privilege) > rank(self.privilege) {
            tracing::error!(
                program = program.path,
                "a task program needs more privilege than its catalog entry declares; not run"
            );
            return Err(Stop::Failed("agent_error"));
        }
        tracing::info!(
            task_id = self.task_id,
            program = program.path,
            "task program starting"
        );
        if program.privilege == Privilege::PackageManager {
            self.steps += 1;
            unit::run(
                self.units,
                self.task_id,
                self.steps,
                program,
                self.limits,
                self.control,
                &self.capture,
            )
        } else {
            spawn::run(
                program.path,
                &program.argv(),
                self.limits,
                self.control,
                &self.capture,
            )
        }
    }

    /// Runs `program` like [`Run::program`], and also returns its own output (bounded like the task's),
    /// for a job that decides from what a program printed. The output is added to the task's as well.
    pub fn program_output(&mut self, program: &Program) -> Result<(Exit, String), Stop> {
        let task = std::mem::replace(&mut self.capture, Arc::new(Mutex::new(Capture::default())));
        let ran = self.program(program);
        let own = std::mem::replace(&mut self.capture, task);
        let (text, _) = spawn::lock(&own).finish();
        spawn::lock(&self.capture).push(text.as_bytes());
        ran.map(|exit| (exit, text))
    }

    /// Adds a line from the agent to the task's output.
    pub fn note(&mut self, line: &str) {
        spawn::lock(&self.capture).note(line);
    }

    /// Adds `$ <program and its arguments>` to the output where the program's own output will follow,
    /// so a reader can tell which step printed what (P3-D01 Q19). Written by the agent, not the VM.
    pub fn heading(&mut self, program: &Program) {
        let mut line = format!("$ {}", program.path);
        for arg in program.argv() {
            line.push(' ');
            line.push_str(arg.as_str());
        }
        self.print(&line);
    }

    /// Adds one line written by the agent to the output, where it is now (not at the end, as
    /// [`Run::note`] does), as one sanitized line.
    pub fn print(&mut self, line: &str) {
        let mut line = crate::logging::sanitize(line, 500).trim_end().to_owned();
        line.push('\n');
        spawn::lock(&self.capture).push(line.as_bytes());
    }

    /// The agent's shutdown flag, for work the job does itself (listing packages).
    pub fn shutdown(&self) -> &Shutdown {
        self.control.shutdown()
    }

    /// Waits up to `pause` with no program running, keeping the server informed (progress). `Err` when
    /// the deadline passes (`TimedOut`), or when the agent stops (`Interrupted`: nothing runs, so even
    /// a task that cannot be interrupted can stop here), or the server cancels an interruptible task.
    pub fn pause(&mut self, pause: Duration) -> Result<(), Stop> {
        let until = Instant::now() + pause.min(self.remaining());
        loop {
            if Instant::now() >= self.limits.deadline {
                return Err(Stop::TimedOut);
            }
            if self.control.cancel_requested() && self.limits.interruptible {
                return Err(Stop::Cancelled);
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(());
            }
            if self.control.shutdown().wait(left.min(PAUSE_TICK)) {
                return Err(Stop::Interrupted);
            }
        }
    }

    /// Time left before the deadline.
    pub fn remaining(&self) -> Duration {
        self.limits
            .deadline
            .saturating_duration_since(Instant::now())
    }
}

/// How often [`Run::pause`] looks at the deadline, the cancel, and the shutdown.
const PAUSE_TICK: Duration = Duration::from_secs(1);

fn rank(privilege: Privilege) -> u8 {
    match privilege {
        Privilege::ReadOnly => 0,
        Privilege::ServiceManager => 1,
        Privilege::PackageManager => 2,
    }
}

/// The registry of task implementations: this build's [`Executor`].
pub struct Registry {
    tasks: Vec<Box<dyn TaskImpl>>,
    settings: TaskSettings,
    units: Box<dyn unit::Units>,
}

impl Registry {
    /// The task types this agent version implements ([`super::IMPLEMENTED`]). `package_report` asks the
    /// agent's package report loop for a report (`apply_package_updates`).
    pub fn production(
        settings: TaskSettings,
        package_report: Arc<dyn super::apply_updates::PackageReport>,
    ) -> Self {
        let tasks: Vec<Box<dyn TaskImpl>> = vec![
            // --- P3-AGENT-UPDATES (#37): apply_package_updates (DEC-16), apt on Debian. ---
            Box::new(super::apply_updates::ApplyUpdates::production(
                package_report,
            )),
            // --- end of #37's block ---
        ];
        Self::new(tasks, settings, Box::new(unit::Systemd))
    }

    pub fn new(
        tasks: Vec<Box<dyn TaskImpl>>,
        settings: TaskSettings,
        units: Box<dyn unit::Units>,
    ) -> Self {
        Self {
            tasks,
            settings,
            units,
        }
    }

    /// The type ids in the registry, sorted.
    pub fn ids(&self) -> Vec<&'static str> {
        let mut ids: Vec<_> = self.tasks.iter().map(|t| t.type_id()).collect();
        ids.sort_unstable();
        ids
    }

    fn get(&self, task_type: &str) -> Option<&dyn TaskImpl> {
        self.tasks
            .iter()
            .find(|t| t.type_id() == task_type)
            .map(|t| &**t)
    }

    fn entry(task_type: &str) -> Option<&'static super::catalog::TaskType> {
        Catalog::embedded().ok()?.get(task_type)
    }

    fn prepare(&self, task: &Delivered) -> Result<Box<dyn Job>, &'static str> {
        let implementation = self.get(&task.task_type).ok_or("not_supported")?;
        implementation.prepare(&task.parameters, &self.settings)
    }
}

impl Executor for Registry {
    fn implements(&self, task_type: &str) -> bool {
        self.get(task_type).is_some() && Self::entry(task_type).is_some()
    }

    fn check(&self, task: &Delivered) -> Result<(), &'static str> {
        self.prepare(task).map(drop)
    }

    fn run(&self, task: &Delivered, control: &dyn Control) -> Option<Execution> {
        let started_at = SystemTime::now();
        let started = Instant::now();
        let capture = Arc::new(Mutex::new(Capture::default()));
        let mut execution = Execution {
            outcome: Outcome::Failed,
            reason: Some("agent_error"),
            exit_status: None,
            started_at,
            finished_at: started_at,
            output: String::new(),
            output_truncated: false,
            details: Map::new(),
        };
        // Checked again: run is reached only after check passed, but the job comes from here.
        let (Some(entry), Ok(job)) = (Self::entry(&task.task_type), self.prepare(task)) else {
            execution.finished_at = SystemTime::now();
            return Some(execution);
        };
        let timeout = task.timeout_seconds.min(entry.timeout_seconds).max(1);
        let mut run = Run {
            task_id: &task.id,
            privilege: entry.privilege,
            limits: spawn::Limits {
                deadline: started + Duration::from_secs(timeout),
                interruptible: entry.interruptible,
            },
            control,
            units: &*self.units,
            capture: Arc::clone(&capture),
            steps: 0,
        };
        let ended = job.run(&mut run);
        drop(run);
        execution.reason = None;
        match ended {
            Ok(finish) => {
                execution.outcome = finish.outcome;
                execution.reason = finish.reason;
                execution.exit_status = finish.exit_status;
                execution.details = finish.details;
            }
            Err(Stop::TimedOut) => {
                execution.outcome = Outcome::TimedOut;
                spawn::lock(&capture).note(&format!(
                    "the task ran past its deadline of {timeout} seconds and was stopped"
                ));
            }
            Err(Stop::Cancelled) => {
                execution.outcome = Outcome::Cancelled;
                spawn::lock(&capture).note("the task was cancelled and stopped");
            }
            Err(Stop::Interrupted) => {
                execution.reason = Some("interrupted");
                spawn::lock(&capture).note("the agent stopped, and stopped the task");
            }
            Err(Stop::Detached) => return None,
            Err(Stop::Failed(reason)) => execution.reason = Some(reason),
        }
        let (output, truncated) = spawn::lock(&capture).finish();
        execution.output = output;
        execution.output_truncated = truncated;
        execution.finished_at = SystemTime::now();
        Some(execution)
    }

    fn recover(&self, task: &ledger::Task) -> Recovered {
        // Only a type this version runs can have left a unit; this build has none, so nothing is asked.
        if !task
            .task_type
            .as_deref()
            .is_some_and(|t| self.implements(t))
        {
            return Recovered::Nothing;
        }
        let capture = Arc::new(Mutex::new(Capture::default()));
        let (exits, timed_out) = match unit::recover(&*self.units, &task.id, &capture) {
            unit::Found::None => return Recovered::Nothing,
            unit::Found::Running => return Recovered::Running,
            unit::Found::Ended(exits, timed_out) => (exits, timed_out),
        };
        let mut capture = spawn::lock(&capture);
        capture.note(
            "the agent restarted while this task ran in its own unit; this is what the unit reported",
        );
        // The type may know what its units' exits mean (P3-AGENT-UPDATES); otherwise the job never saw
        // its programs end, so it decided nothing after them (a later step, its details): even a clean
        // exit of every unit is only "it ran, and the agent was not there".
        let (text, _) = capture.finish();
        let mut notes = Vec::new();
        let decided = task
            .task_type
            .as_deref()
            .and_then(|t| self.get(t))
            .and_then(|t| t.recovered(&exits, timed_out, &text, &mut notes));
        for note in &notes {
            capture.note(note);
        }
        let (output, output_truncated) = capture.finish();
        let finished_at = SystemTime::now();
        let started_at = task
            .started_at
            .as_deref()
            .and_then(|t| humantime::parse_rfc3339(t).ok())
            .unwrap_or(finished_at);
        let exit_status = exits.last().and_then(|(_, e)| e.code);
        let finish = decided.unwrap_or_else(|| {
            let (outcome, reason) = if timed_out {
                (Outcome::TimedOut, None)
            } else if exits.iter().all(|(_, e)| e.success()) {
                (Outcome::Failed, Some("interrupted"))
            } else {
                (Outcome::Failed, Some("nonzero_exit"))
            };
            Finish {
                outcome,
                reason,
                exit_status,
                details: Map::new(),
            }
        });
        Recovered::Ended(Execution {
            outcome: finish.outcome,
            reason: finish.reason,
            exit_status: finish.exit_status,
            started_at,
            finished_at,
            output,
            output_truncated,
            details: finish.details,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
