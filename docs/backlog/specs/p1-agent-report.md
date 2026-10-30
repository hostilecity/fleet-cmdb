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
- Implementation notes (agent behaviour the server side relies on):
  - Jitter subtracts up to 10% from the interval, so a heartbeat is never later than the interval in force.
  - Until [P1-UPDATES](p1-updates.md) adds the directives to the contract, the agent accepts `directives` as the v1 array (every entry ignored and logged by its `type`) or as an object keyed by directive name: `intervals` with `heartbeat_seconds` and `inventory_seconds` (whole seconds, each optional), and `agent_update` (kept for the updater, not acted on before P1-AGENT-UPDATE). Any other name, field, or malformed value is ignored and logged once; the heartbeat still counts as accepted.
  - The first accepted heartbeat of each process is recorded in the state directory (`heartbeat.json`: process id, time, agent version), once per start, so `fleet-agent install` can confirm the service itself reaches the server ([P1-AGENT-INSTALL](p1-agent-install.md)).
  - A server interval is clamped to the config's `min..=max`. An interval missing from a response returns to the configured value. Server intervals are not persisted; after a restart the configured values apply until the first heartbeat response.
  - A difference of more than 5 minutes between `server_time` and the agent clock is logged when it starts and when it ends.

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
- Implementation notes:
  - The stable check runs every 60 seconds. The hash covers the stable facts and the agent version (DEC-07); free memory, free disk space, and uptime are excluded.
  - The startup report is always sent (FR-1.3). The saved record (`inventory.json` in the state directory, written atomically after each accepted report) is the change baseline across restarts: the startup report logs whether the stable facts changed and whether the host rebooted since the last accepted report, and no extra change report follows it. A missing or corrupt record counts as none.
  - While a report waits for its retry, a stable change or the report reaching one inventory interval in age replaces it with a new report (new id); the retry wait still applies. Nothing older is ever sent.
  - A report rejected for its content (`400`, `413`, `422`) is not retried, since the same body would be rejected again; the next report follows the normal schedule. Other failures retry with the same id and body.

### Acceptance criteria

- [ ] A retried send uses the same report id (unit test)
- [ ] Changing a stable field (for example adding an address) triggers an extra report within the check interval
- [ ] A volatile-only change does not trigger an extra report
- [ ] A rejected report logs the server's error code and message and the agent keeps running
