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
- Hint for the heartbeat response `directives` ("tasks available") so agents can poll promptly without tight polling.

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
