# P3-TASK-CONTROLS: Leases, expiry, timeouts, cancellation, allowlists, and task audit

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-S05: Lease, expiry, and timeout jobs; cancellation semantics

### Scope

- Recurring jobs (at least every minute): expire queued tasks past their expiry; return claimed-but-unstarted tasks to `queued` when the lease lapses; mark started tasks `failed` with `lease_expired` if the agent stops reporting; mark `running` tasks `timed_out` after the deadline plus a grace period if no result arrives.
- Cancellation:
  - `queued` or claimed-but-unstarted: becomes `cancelled` immediately and is never delivered or, if already delivered, the agent's start acknowledgement is refused and the agent is told to drop it.
  - `running` and interruptible: a cancel directive is delivered on the agent's next poll or progress response.
  - `running` and not interruptible: the task keeps running; `cancel_requested` is recorded and no further queued task of the same batch is started. The dashboard says this plainly.
- All state changes by jobs are audited ([P3-S07](p3-task-controls.md)) with the system as actor.
- **Confirmed by the owner (2026-11-08, mockup Q17):** FR-3.2 says that for non-interruptible running tasks "cancellation takes effect before the next task starts". This reads as: the running task is not stopped, it keeps its real state with "cancel requested" beside it, and no task of the same batch that has not started will start. Recorded in [DEC-14](../../decisions/0014-task-trust-model.md).

### Acceptance criteria

- [ ] AC-3.5 (server half): a task with no result after deadline and grace is `timed_out`
- [ ] AC-3.6: cancelling a queued task means it is never delivered
- [ ] AC-3.8: expiry works as specified
- [ ] Jobs are idempotent and safe if run concurrently

### Handed over from P3-TASK-API (#30)

- The claim lease (5 minutes), the running lease (deadline plus 5 minutes' grace), and the output limit (64 KiB) are constants (`AgentTasks::CLAIM_LEASE`, `AgentTasks::RESULT_GRACE`, `TaskOutput::LIMIT_BYTES`). P3-S06 makes them settings.
- A claimed task past its `expires_at` is no longer delivered, and it blocks its host's poll until this job requeues it and then expires it.
- The cancel directive goes in `task-poll.response` and `task-progress.response` as an optional field (additive). A start for a task that is not claimed already answers `run: false`.
- A `start` that arrives after the task was requeued (threat model L2) answers `run: false` with `state: queued`. Decide here whether that stays so.

## P3-S06: Server-side allowlists and task settings

### Scope

- Settings and UI for: the restartable-services allowlist (empty by default, optional per tag, per [DEC-15](../../decisions/0015-restartable-services.md)), the protected-services list, maximum hosts per batch, default expiry per task type, output limit, and task poll interval hint.
- Restart parameters validate against the allowlist at creation and again at claim time.
- Every change to an allowlist or limit is audited with before and after values and requires the second factor from [P3-S09](p3-dash-create.md).
- With an empty allowlist the restart task cannot be created at all and the UI says why.

### Acceptance criteria

- [ ] With the default empty allowlist, creating a restart task is refused
- [ ] A service removed from the allowlist while a task is queued causes that task to be refused at claim time
- [ ] Allowlist changes appear in the audit log with before and after

## P3-S07: Task audit trail completeness

### Scope

- Audit entries (with actor) for: batch created, task created, claimed, started, cancelled (requested and effective), expired, lease expired, timed out, result received (with outcome), refused, and allowlist and limit changes.
- Operator-initiated entries have the operator as actor; agent-initiated entries have the host; time-based changes have the system.
- Task output is **not** stored in the audit log; entries reference the task.
- Confirm audit entries for tasks are not pruned (consistent with [DEC-07](../../decisions/0007-snapshots-and-retention.md)), with a spec guarding it.
- A checklist spec that walks every transition and asserts an entry exists.

### Acceptance criteria

- [ ] Every state transition produces exactly one audit entry with the right actor
- [ ] No secrets or output in audit entries
- [ ] Retention job leaves task audit entries untouched

## As built

### P3-S05: jobs and cancellation

- **Jobs:** `TaskExpiryJob` and `TaskLeaseJob`, every minute in development and production (`config/recurring.yml`), call `TaskLeases.expire!` and `TaskLeases.lapse!` (`cmdb/app/services/task_leases.rb`). Each task is taken `FOR UPDATE SKIP LOCKED` in its own short transaction, so overlapping runs and polls never handle a task twice (threat model L6); a run handles at most 1000 tasks.
- **Expiry:** a queued task at its `expires_at` becomes `expired`. A claimed task the agent never started is requeued, then expired (two entries). The expiry is the one the task was created with.
- **Leases:** a claimed task whose lease lapsed goes back to `queued`. A running task with no result at its deadline plus 5 minutes' grace becomes `timed_out` if the agent was heard from after the deadline (a heartbeat or progress), or `failed` with `lease_expired` if it was not (it stopped reporting). A result that arrives later is kept as a late result (P3-S04). The claim lease (5 minutes) and the grace (5 minutes) stay constants (`AgentTasks::CLAIM_LEASE`, `AgentTasks::RESULT_GRACE`): the approved mockup has no setting for them.
- **#30 handover fixed:** a claimed task past its expiry no longer blocks its host. The poll requeues and expires it at once (system as actor) and moves on to the next task.
- **Start after requeue (threat model L2), decided:** it stays `run: false` with `state: queued`, and the server changes nothing. The agent executes only after `run: true`, so it has not run the task. The next poll claims it again and delivers the same id. The agent never runs an id twice, so it closes the task with a result: outcome `failed`, reason `not_run` (new in `task-result.request`). The server accepts that for a claimed task, and for a queued one this host claimed before (so the agent may send it before the next poll); it refuses it for a running task, which was told to run (`409`). It is audited as `task.failed` with the host as actor, and the host is free for its next task instead of waiting for the expiry. `tasks_guard` v02 allows queued to failed only with `not_run`. The agent side is #34 and #35.
- **Cancellation** (`TaskCancellation`, `POST /tasks/:id/cancel` and `POST /tasks/batches/:id/cancel`, `require_second_factor "cancel_task"`; any operator, Q23):
  - queued or claimed: `cancelled` now, operator as actor. A claimed task's start is then answered `run: false`.
  - running and interruptible: `cancel_requested_at` and `cancel_requested_by` are recorded (`task.cancel_requested`), and the poll and progress responses carry `"cancel": {"id": ...}` until the agent reports. The agent's `cancelled` result ends it, host as actor.
  - running and not interruptible: the request is recorded and the task runs to completion. Every task of its batch that has not started is cancelled now. No directive is sent.
  - A batch cancel does all of that for each task of the batch. Finished tasks are never changed.
  - `tasks_guard` v02 keeps a cancel request as recorded: set once, only on a running task, with the operator.
  - The confirmation dialogs and the task and batch pages are P3-DASH-TASKS (#33). Until then the endpoints redirect back with a notice in the mockup's words.
- **Revoked, re-enrolling, or retired host (threat model V9):** its queued and claimed tasks are cancelled in the same transaction, with the same actor (`Host::TASK_CANCELLING_EVENTS`), so tasks meant for one machine never reach the next. A running task ends by its result or its lease.
- **Directive delivery:** the agent polls only between tasks, so for a running task the cancel reaches it through the progress response. An interruptible type that never sends progress gets the directive only if it polls (P3-A02, #34).

### P3-S06: settings

- **Settings: Tasks** (`/settings/tasks`, `TaskSettingsController`, `TaskSettings`), as `settings-tasks.html` draws it. Every change needs `require_second_factor "change_task_settings"`; a refused code shows the page again with what was typed. Removing a service has a confirmation page that counts the queued restarts it would leave without an entry.
- **Allowlist:** table `task_allowed_services` (service, optional tag, who added it, when). Full `.service` names, lower-case, at most 64 characters, no `@` instances (Q31); at most 64 entries. Protected services are refused, with no override (Q32). Audited as `task_setting.service_added` and `task_setting.service_removed` with the list before and after.
- **Per tag:** `TaskPolicy.refusal(type, parameters, host:)` counts only the entries for every host or for one of the host's tags. At creation, a request needs an entry for the service; then hosts that no entry covers are excluded as `not_allowed_on_server`. At claim time the host's tags as they are then are used.
- **Limits** (Q33), stored in `settings`: hosts per batch 1 to 25 (default 25), output kept 4 to 1024 KiB (default 64), poll hint 10 to 300 s (default 30), expiry per type 1 to 168 hours (default the catalog's 24). One `task_setting.limits_changed` entry per save with before and after. Expiry applies to tasks created afterwards. The poll hint is `poll_seconds` in every `task-poll.response`.
- **Output limit and the agent:** the agent sends at most 131072 characters (`task-result.request`), so a limit above 128 KiB keeps at most what the agent sends.

### P3-S07: audit

- New actions: `task.cancel_requested`, `task_setting.service_added`, `task_setting.service_removed`, `task_setting.limits_changed`, in a "Task settings" group of the audit filter. Lease expiry is `task.failed` with reason `lease_expired`; a result received is the transition it applies (`task.succeeded`, `task.failed`, ...).
- `spec/services/task_audit_trail_spec.rb` walks every transition through the real code paths and checks exactly one entry with the right actor, no output in any entry, and that retention never prunes task entries or tasks.
- "Task creation refused" (mockup audit.html) belongs to the create flow (P3-S08, #32).

