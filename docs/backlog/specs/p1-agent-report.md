# P1-AGENT-REPORT: Agent heartbeat loop and inventory reporter

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-A06: Agent heartbeat loop

### Scope

- Sends a heartbeat immediately on start, then at the configured interval with jitter.
- Payload: host identity, agent version, agent uptime, current time.
- Failures follow the [P1-A02](p1-agent-core.md) backoff policy and never exit the process; the interval resumes on recovery.
- Handles the response envelope (`server_time`, `directives`), ignoring directives it does not understand.
- Applies `directives.intervals` (heartbeat and inventory seconds) within the bounds of its config, so the server can shed load fleet-wide without an agent release ([ADR 0019](../../decisions/0019-scale-direction.md)). `directives.agent_update` is handed to the updater ([P1-AGENT-UPDATE](p1-agent-update.md)).
- Clean shutdown on signal without losing state.

### Acceptance criteria

- [ ] After `enroll` and `run`, the first heartbeat reaches the server within seconds
- [ ] Killing the server for several minutes and restarting it does not crash the agent and heartbeats resume
- [ ] Unknown directives are ignored and logged

## P1-A07: Inventory reporter: startup, interval, and on-change

### Scope

- Builds the inventory report (schema version, report id as UUIDv4, fields, collection warnings) and sends it on startup, every inventory interval, and when a **stable** field changes (a local check at a modest fixed interval comparing a hash of the stable fields).
- Reuses the same report id when retrying a failed send, and generates a new id for a new report.
- Persists the last-reported stable hash and boot identifier in the state directory so a restart does not report spuriously or miss a change.
- Does not queue or replay old reports during an outage; it sends current state when the server returns.
- Logs each report's outcome (sent, duplicate, rejected with reason) with the report id.

### Acceptance criteria

- [ ] A retried send uses the same report id (unit test)
- [ ] Changing a stable field (for example adding an address) triggers an extra report within the check interval
- [ ] A volatile-only change does not trigger an extra report
- [ ] A rejected report logs the server's error code and message and the agent keeps running
