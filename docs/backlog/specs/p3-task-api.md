# P3-TASK-API: Task poll, atomic claim, progress, and result API

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-S03: Task poll and atomic claim API

### Scope

- `POST /api/v1/tasks/poll`: authenticated as the host; returns at most one task for that host (one at a time). Payload contains only task id, type, parameters, deadline, and catalog version: no free-form strings that could be executed.
- Atomic claim: a single conditional update (or `FOR UPDATE SKIP LOCKED`) so two simultaneous polls for the same host cannot both claim the same task. Claim sets a lease.
- Idempotent redelivery: if the agent polls again while it still holds an unstarted claim (for example after restarting), the same task is returned again. A task the server knows was started is never redelivered as runnable.
- `POST /api/v1/tasks/:id/start`: the agent acknowledges that it has recorded the task as started locally; moves `claimed` to `running` (idempotent).
- Expired tasks are never delivered. Another host's tasks cannot be polled or addressed (404).
- Re-validates parameters and allowlists at claim time; a task that no longer validates becomes `refused` on the server with a reason and is not delivered.
- Hint in the heartbeat response `directives` ("tasks available"), as one named directive ([DEC-20](../../decisions/0020-named-heartbeat-directives.md)), so agents can poll promptly without tight polling.

### Acceptance criteria

- [ ] Concurrency test: many parallel polls for one host claim a task exactly once
- [ ] AC-3.8: an expired queued task is never returned
- [ ] A task for host B is not visible to host A in any endpoint
- [ ] A restarted agent that polls again receives an unstarted claimed task once more, and never a started one as runnable

## P3-S04: Task progress and result reporting API

### Scope

- `POST /api/v1/tasks/:id/progress` (optional, for task types that support it) and `POST /api/v1/tasks/:id/result`.
- Result fields: outcome (`succeeded`, `failed`, `timed_out`, `cancelled`, `refused`), exit status, reason code, start and finish times as reported by the agent (stored separately from server receipt time), structured details (for example `reboot_required`), and captured output.
- Output: truncated to a server-defined limit with a clear truncation marker; invalid UTF-8 and control characters sanitised; stored as inert text.
- Idempotent: the same result submitted twice is accepted; a conflicting second result is rejected and logged. Terminal states are immutable; a late result for a task the server already marked `timed_out` or `expired` is stored as an annotation but does not change the state.
- Only the host that owns the task can report on it.
- Agent-side `refused` results are recorded with their reason, which is how AC-3.1 is observed.

### Acceptance criteria

- [ ] Re-sending a result changes nothing; a conflicting result is rejected
- [ ] Oversize output is truncated and marked
- [ ] Reporting on another host's task fails
- [ ] Output containing markup or control characters is stored safely (rendering covered in [P3-S10](p3-dash-tasks.md))

## As built

### Contract

- Schemas and examples in `docs/api/`: `task-poll.*`, `task-start.*`, `task-progress.*`, `task-result.*`, the `tasks_available` heartbeat directive, and error code `409 task_conflict`. The README's "Tasks" section is the agent's reference. The contract was pushed first, so the agent poller (P3-A02, #34) could build against it.
- **The deadline is `timeout_seconds`**, relative to the start, so the agent's clock does not matter. The agent uses the lower of it and its own catalog's timeout.
- **Start answers `run`.** The agent runs a task only after `run: true` (the task is `running` on the server). For any other state it records that it did not run the task and drops it. This is the channel P3-S05 uses to refuse the start of a cancelled task.
- **409 means stop retrying.** `task_conflict` is answered for a result that differs from the one the server has, and for a result the task's state cannot take (for example `succeeded` for a task that never started, or any result for a queued one).

### P3-S03

- `AgentTasks` (`cmdb/app/services/agent_tasks.rb`) and `Api::V1::TasksController`. Every task request locks the host row (`AgentHostLock`) in one transaction, so one host's polls, starts, and results never interleave. The claim also locks the task `FOR UPDATE SKIP LOCKED`. The concurrency spec runs 8 parallel polls and sees one claim.
- **One task at a time per host:** a running task makes the poll return `null`. A claimed, unstarted task is returned again with a fresh lease (5 minutes, `AgentTasks::CLAIM_LEASE`), but not after its `expires_at`: then it goes back to the queue and expires at once, and the poll moves on (P3-S05, #31).
- **Expiry uses the database clock:** the claim query checks `expires_at > clock_timestamp()` in the statement that locks the row (threat model L1).
- **Claim-time revalidation** is `Task#refusal_reason` (catalog and server policy) on every delivery and again at start. A task that fails is `refused` with its reason and the **system** as actor (the server decided, not the agent), and the poll tries the next, at most 25 per poll. The host's reported capabilities are not checked again: the agent refuses locally, which is how AC-3.1 is observed.
- **Start** sets the running lease to the deadline plus 5 minutes' grace (`AgentTasks::RESULT_GRACE`). P3-S05 decides what happens when it lapses.
- **The `tasks_available` directive** is one indexed `SELECT` per heartbeat (a heartbeat is now at most 9 queries, still one write).

### P3-S04

- **Columns:** `tasks` gains `progress_percent`, `progress_reported_at`, `result_report_id`, `result_digest`, `result_received_at`, and `result_details`. New table `task_late_results`: at most one per task, never changed or deleted (`task_late_results_guard`).
- **Progress** stores `percent` (0 to 100, or null) while the task is running and is ignored otherwise. It does not extend the lease. Any type may send it; the catalog has no "supports progress" flag.
- **Idempotency:** a result is identified by a SHA-256 digest of everything but its `report_id` and versions (`AgentTasks.result_digest`). The same digest again is `duplicate: true` whatever the `report_id`. A different one is `409`, audited as `task.result_conflict` and logged without output.
- **Outcomes** (`AgentTasks::AGENT_FROM`, narrower than `Task::TRANSITIONS`, which also serves the operator and the server): `failed` and `refused` from claimed or running, `succeeded` and `timed_out` from running, `cancelled` from running for an interruptible type only. So an agent can never cancel or refuse a queued task, or cancel a claimed one. An applied result writes the transition's audit entry with the host as actor. The agent's reasons are a subset: `lease_expired` and `not_allowed_on_server` are the server's only.
- **Late results:** a result for a task the server ended itself (no agent result recorded) is kept in `task_late_results`, audited as `task.late_result`, and answered `applied: false`. The task does not change.
- **Details** kept: `reboot_required`, `services_needing_restart`, `packages_upgraded`, `packages_held_back` (the last two added by P3-AGENT-UPDATES for the task detail mockup's "14 upgraded, 1 held back"), `unit_active`, `reports_sent`. Other keys are ignored. Stored details are bounded at 32 KiB as JSON; the largest the schema allows is about 26 KiB.
- **Output** (`TaskOutput`): invalid UTF-8 replaced, terminal escape sequences removed whole in both their ESC and C1 forms (a string sequence without a terminator on its line loses only its introducer, so it cannot swallow later output), control characters other than tab and newline removed, Unicode bidi overrides and isolates removed. Over the output limit (64 KiB by default, `TaskOutput::LIMIT_BYTES`; a setting since #31), the start and end are kept with a marker line in the middle, and `output_truncated` is set. The agent sends at most 131072 characters. A result body may be 1 MiB.
- **Done in P3-TASK-CONTROLS (#31):** the lease and expiry jobs, the output limit as a setting, the cancel directive in the poll and progress responses, and the late `start` for a requeued task (threat model L2). See [p3-task-controls.md](p3-task-controls.md), "As built".
