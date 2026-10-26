# P3-DASH-TASKS: Dashboard: task list, detail, batch progress, and cancel

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- Task list filterable by host, type, and state.
- Task detail: state, target host, parameters, timeline of state changes with timestamps (server and agent times), output (escaped, with truncation marker), result, reason codes in plain language (including `interrupted` and `lease_expired`), and `reboot_required`.
- Batch view with per-host progress counts (for example 6 succeeded, 1 running, 1 failed), updating live (Turbo), and per-host rows linking to task detail.
- Cancel with explicit confirmation and the plain explanation of what cancellation can and cannot do for a running, non-interruptible task ([P3-S05](p3-task-controls.md)).
- All output rendered as escaped text.

## Acceptance criteria

- [ ] Batch counts match the underlying task states and update without reload
- [ ] Task output with markup renders as text
- [ ] Cancelling a queued task shows `cancelled`; cancelling a running non-interruptible task shows the explanatory state
