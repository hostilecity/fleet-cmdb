# P3-AGENT-TASKS: Agent tasks: refresh_reports and restart_service

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-A04: Agent task: refresh_reports

### Scope

- Implements the `refresh_reports` task: re-collect and send the selected reports (inventory, config, packages) immediately, reusing the collectors and the [DEC-13](../../decisions/0013-on-demand-reports.md) mechanism rather than duplicating them.
- The parameter is an enumerated list of report types.
- Interruptible; result details list which reports were sent.

### Acceptance criteria

- [ ] The task produces fresh reports at the server and a `succeeded` result
- [ ] An invalid report type is refused
- [ ] Concurrent scheduled reporting and the task do not produce duplicate snapshots

## P3-A06: Agent task: restart_service

### Scope

- Parameter: `service` with a strict pattern. The agent refuses unless the name is in **both** the server-supplied allowlist reference (validated by the server) **and** the agent's own local allowlist ([P3-A01](p3-agent-ledger.md)), and is not on the protected list ([DEC-15](../../decisions/0015-restartable-services.md)).
- Runs the service manager with an absolute path and a fixed argument vector, with the service name as a single validated argument after an end-of-options marker.
- Verifies the result afterwards (the unit is active) and reports `succeeded` or `failed` with captured output.
- Never restarts the agent's own unit or the SSH service unless the owner explicitly allowed it ([DEC-15](../../decisions/0015-restartable-services.md)).
- Timeout per catalog; not interruptible once started.

### Acceptance criteria

- [ ] AC-3.9: a service on the server allowlist but missing from the local one is refused
- [ ] A name containing option-like or shell-like characters is refused before any process starts
- [ ] Restarting an allowed test service works and reports success
- [ ] The agent's own unit is refused by default
