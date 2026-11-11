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

## As built (#33)

- **Tasks** (`GET /tasks`, `TasksController#index`, `TaskList`), as `tasks.html` draws it (Q2): one row per task, newest first, with the state as a word and a lamp and a short line saying what it means. Chips for All, Waiting or running, Failed/timed out/refused/expired, Succeeded, and Cancelled, with counts for the other filters. A plain GET form filters by host (name or hostname, part of it), type, state (one state or a chip's group), and batch. Keyset pages of 50 on the task id, as on the audit log. Without a second factor "New task" is replaced by an explanation (Q12).
- **A task** (`GET /tasks/:id`): the state and reason in plain words with the code beside them (`task-states.html`, Q21), including `interrupted`, `lease_expired`, refusals by the agent or by the server at claim, timed out by the agent (with the `dpkg --configure -a` advice for package updates, Q20) or by the server, and the three ways a task is cancelled. A running task that cannot be interrupted and has a cancel request keeps its real state with "cancel requested" beside it, and keeps the line after it finishes (Q17). Then what it reported (`reboot_required`, services using old libraries, `unit_active`, reports sent), the task facts and parameters, the timeline, the output, a late result if one came (kept beside the task, P3-S04), and the task's audit entries.
- **Timeline** (Q18): the task's audit entries, which are exactly its state changes and cancel requests, plus the last progress report. The agent's own start and finish times sit beside the server's, with "Clock differs by" when they differ by more than a minute. The server stores only the latest progress, so the timeline has one progress row, not one per report.
- **Output** (FR-3.3, Q19, Q22): the stored text (already sanitised by `TaskOutput`) in a `<pre>`, escaped by ERB and never marked safe. A truncated output says so above the box; the cut itself is the line `TaskOutput` writes, since the cut position is not stored separately. `GET /tasks/:id/output` serves the same bytes as `text/plain` with `Content-Disposition: attachment` and `nosniff`.
- **Batch progress** (`GET /tasks/batches/:id`), as `batch.html` and `batch-partial.html` draw it: a cell for every state, zeros dimmed (Q14; "Waiting" is queued and claimed), counted from the task rows on every render; the bar under it (widths as grow classes, since the CSP forbids inline styles); the counts in words with how many need a reboot; rows problems first (Q15) linking to each task; hosts left out with the reason recorded at creation; the outcome notice (in progress, cancel requested and finishing, or finished, red when something failed); and "Run again on the hosts that did not succeed" (Q16), which opens the create flow's confirmation for those hosts, checked again from scratch.
- **Live updates** (Turbo, as the fleet pages): `Task` and `TaskLateResult` enqueue `TaskBroadcastJob` after commit, which sends a page refresh on the `tasks` stream. The list, task, batch, and host Tasks pages subscribe to it and morph in place. One job per changed task; Turbo debounces the refreshes in the browser.
- **Cancel** (`GET /tasks/:id/cancel`, `GET /tasks/batches/:id/cancel`, then the P3-S05 POSTs): a confirmation page per case in `cancel.html`'s words, with the code box (or "checked" inside the 5-minute window). The button is named by what it can do: "Cancel task" (queued, claimed), "Stop task" (running, interruptible), and for a running task that cannot be interrupted "Cancel what has not started" or, with nothing else waiting, "Record a cancel request anyway" (Q23). The batch dialog counts what will and will not change. A refused code draws the confirmation again (403, 429 when locked). After a cancel the answer goes to the task's or the batch's page.
- **Host Tasks tab** (`GET /hosts/:id/tasks`, `host-tasks.html`, Q34): what the agent will run as it last reported, what is waiting or running now, whether its latest package update reported a reboot as required, and its last 20 tasks, with a link to the Tasks page filtered by its hostname. The tab shows "N running" or "N waiting". "Run a task on this host" in the header of an active host opens the create flow with the host chosen.
- **Audit log:** entries for a task or a batch link to its page.
