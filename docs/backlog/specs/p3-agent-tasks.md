# P3-AGENT-TASKS: Agent tasks: refresh_reports and restart_service

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-A04: Agent task: refresh_reports

### Scope

- Implements the `refresh_reports` task: re-collect and send the inventory, config, and package reports immediately, reusing the collectors and the [DEC-13](../../decisions/0013-on-demand-reports.md) mechanism rather than duplicating them.
- No parameters: it always refreshes all three, as the catalog ([P3-S01](p3-task-model.md)) and the dashboard's "Request fresh reports" do. (This spec first said "an enumerated list of report types"; P3-S01 settled on none, and #36 follows the catalog.)
- Interruptible; result details list which reports were sent.

### Acceptance criteria

- [ ] The task produces fresh reports at the server and a `succeeded` result
- [ ] Any parameter (for example a list of report types, valid or not) is refused `invalid_params`
- [ ] Concurrent scheduled reporting and the task do not produce duplicate snapshots

## P3-A06: Agent task: restart_service

### Scope

- Parameter: `service` with a strict pattern. The agent refuses unless the name is in **both** the server-supplied allowlist reference (validated by the server) **and** the agent's own local allowlist ([P3-A01](p3-agent-ledger.md)), and is not on the protected list ([DEC-15](../../decisions/0015-restartable-services.md)).
- Runs the service manager with an absolute path and a fixed argument vector, with the service name as a single validated argument after an end-of-options marker.
- Verifies the result afterwards (the unit is active) and reports `succeeded` or `failed` with captured output.
- Never restarts a protected service: the agent's own units, the SSH service, systemd's own units, networking, or D-Bus, even if listed; there is no override ([DEC-15](../../decisions/0015-restartable-services.md), owner 2026-11-08).
- Timeout per catalog; not interruptible once started.

### Acceptance criteria

- [ ] AC-3.9: a service on the server allowlist but missing from the local one is refused
- [ ] A name containing option-like or shell-like characters is refused before any process starts
- [ ] Restarting an allowed test service works and reports success
- [ ] The agent's own unit is refused by default

## Implementation notes (#36)

- **`refresh_reports`** (`agent/src/tasks/refresh_reports.rs`, `agent/src/report/refresh.rs`). The task asks the three report loops through a shared `Refresh`; each loop takes the ask on its next poll (at most 5 s) together with any `report_request` directive and calls its reporter's `request()`, so one report answers both, and a scheduled report due at the same time is not sent beside it. The reporter tells its loop how each requested report ended (accepted, or rejected for its content) and when it was collected; only a report collected after the task asked counts. Result: `succeeded` with `details.reports_sent` = `config`, `inventory`, `packages` when all three are accepted; `failed`/`agent_error` when the server rejects one for its content (`reports_sent` lists the accepted ones); `timed_out` at the catalog's 600 s when one cannot be sent. A cancel or the agent stopping ends the wait and withdraws the asks not yet taken. There is no agent-side cool-down: one task runs at a time per host (P3-S03), each needs an operator with TOTP step-up (P3-S09), and the loops send one report per type however the asks overlap. No program is run.
- **`restart_service`** (`agent/src/tasks/restart_service.rs`). Checks with nothing run, in order: `invalid_params` (the catalog's pattern, so no option-like, glob, path, or shell characters, and `.service` only); `protected_service` (DEC-15's list, template instances included, and any name that is a symbolic link, at any step of its chain, to a protected unit in a directory of systemd's unit search path); `not_allowed_locally` (exact match in `[tasks] allowed_services`; a template instance such as `postgresql@17-main.service` must be listed by its full name). Then `/usr/bin/systemctl restart -- <unit>`, a 2 s settle, and `systemctl is-active -- <unit>` every second for up to 15 s more; if the unit never becomes active, `systemctl status --no-pager --full --lines=20 -- <unit>` goes into the output. `succeeded` with `details.unit_active: true`, or `failed`/`nonzero_exit` with the exit status of the restart or of the last `is-active`. Not interruptible.
- **Evidence.** Unit tests in both files; the end-to-end test `report::tests::a_refresh_reports_task_sends_one_fresh_report_of_each_type_through_the_report_loops` (poll, start, three fresh reports, one per type beside the startup ones, and a schema-valid result); `scripts/task-privilege-smoke.sh` restarts a throwaway `cmdb-privsmoke-restart.service` with the real type under the agent unit's sandbox and checks that the smoke test's own `fleet-agent-*` unit is refused. The spec asks for no Debian 13 VM run, so `scripts/vm-test.sh` is unchanged; the owner's test-VM check of each type under the installed unit is in `docs/operations/agent-task-privileges.md`.
