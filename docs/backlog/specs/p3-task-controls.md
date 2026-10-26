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
- **Interpretation to confirm with the owner:** FR-3.2 says that for non-interruptible running tasks "cancellation takes effect before the next task starts". This issue reads that as: the running task is not stopped, and no queued task in the same batch starts. Confirm in [DEC-14](../../decisions/0014-task-trust-model.md).

### Acceptance criteria

- [ ] AC-3.5 (server half): a task with no result after deadline and grace is `timed_out`
- [ ] AC-3.6: cancelling a queued task means it is never delivered
- [ ] AC-3.8: expiry works as specified
- [ ] Jobs are idempotent and safe if run concurrently

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
