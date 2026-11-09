//! The seam where the task executor plugs in (P3-A02 for the seam, P3-A03 for the executor).
//!
//! The poller ([`super::poller`]) owns the ledger and the server conversation; an [`Executor`] owns
//! what a task type does. The poller asks it three things, in this order, and nothing else:
//!
//! 1. [`Executor::implements`]: whether this agent version has the type at all. A type it lacks is
//!    refused `not_supported`.
//! 2. [`Executor::check`]: the strict checks that need the type's own knowledge, with nothing run:
//!    typed parameters (`invalid_params`), the local service allowlist (`not_allowed_locally`), a
//!    protected unit (`protected_service`). P3-A03 and P3-A06 fill these in.
//! 3. [`Executor::run`]: only after the `started` record is on disk and the server accepted `start`.
//!
//! The checks the poller makes itself, before any of these, are the ones that need no type: the type is
//! in the embedded catalog (`unknown_type`) and the owner enabled it here (`not_enabled_locally`).
//!
//! This build has no executor: [`NoExecutor`] implements nothing ([`super::IMPLEMENTED`] is empty),
//! so every task is refused `not_supported` before anything is recorded as started, and `run` is never
//! reached. If it were, it runs nothing and says so.

use std::time::SystemTime;

use serde_json::{Map, Value};

use super::ledger::Outcome;
use crate::shutdown::Shutdown;

/// A task as the poll delivered it: only what the API carries (P3-S03), never a command.
#[derive(Debug, Clone, PartialEq)]
pub struct Delivered {
    /// The task's UUID.
    pub id: String,
    /// The catalog type id.
    pub task_type: String,
    /// Parameters, still to be checked by the type's typed struct ([`Executor::check`]).
    pub parameters: Value,
    /// When the server stops waiting for the result (RFC 3339), if it sent one.
    pub deadline: Option<String>,
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

/// Runs task types (P3-A03's registry).
pub trait Executor: Send + Sync {
    /// Whether this agent version has an implementation of `task_type`.
    fn implements(&self, task_type: &str) -> bool;

    /// The type's own checks, with nothing run. `Err` is the refusal reason code.
    fn check(&self, task: &Delivered) -> Result<(), &'static str>;

    /// Runs the task. Called once per task id, ever, after `started` is durable and the server
    /// accepted `start`. It must return when `shutdown` is requested, with what it knows.
    fn run(&self, task: &Delivered, shutdown: &Shutdown) -> Execution;
}

/// The executor of this build: none. Every type is unsupported, so the poller refuses every task
/// `not_supported` and never records one as started.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoExecutor;

impl Executor for NoExecutor {
    fn implements(&self, task_type: &str) -> bool {
        super::IMPLEMENTED.contains(&task_type)
    }

    fn check(&self, _: &Delivered) -> Result<(), &'static str> {
        Err("not_supported")
    }

    fn run(&self, _: &Delivered, _: &Shutdown) -> Execution {
        // Unreachable: `implements` is false for every type. Should it ever be reached, run nothing.
        let now = SystemTime::now();
        Execution {
            outcome: Outcome::Failed,
            reason: Some("agent_error"),
            exit_status: None,
            started_at: now,
            finished_at: now,
            output: String::new(),
            output_truncated: false,
            details: Map::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_build_implements_nothing_and_runs_nothing() {
        let task = Delivered {
            id: "0b5c8a4e-1d6f-4a3b-9c2d-7e8f9a0b1c2d".into(),
            task_type: "refresh_reports".into(),
            parameters: serde_json::json!({}),
            deadline: None,
            catalog_version: 1,
        };
        for id in super::super::catalog::Catalog::embedded().unwrap().ids() {
            assert!(!NoExecutor.implements(id), "{id}");
        }
        assert_eq!(NoExecutor.check(&task), Err("not_supported"));
        let shutdown = Shutdown::default();
        let ran = NoExecutor.run(&task, &shutdown);
        assert_eq!(ran.outcome, Outcome::Failed);
        assert!(ran.output.is_empty());
    }
}
