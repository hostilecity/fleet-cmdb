# P1-HEARTBEAT: Heartbeat endpoint and liveness evaluation

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-S07: Heartbeat endpoint

### Scope

- `POST /api/v1/heartbeat` accepting host identity, agent version, agent uptime, and the agent's current time.
- Updates only `last_seen_at` (server time), agent version, agent schema version, and the agent-reported time (stored separately, never used for liveness). Sets `first_seen_at` on the first successful heartbeat.
- If the host was not `online`, it becomes `online` in the same transaction and a status history row is written ([P1-S09](p1-heartbeat.md) owns the table), so recovery shows immediately rather than after the next job run.
- Response: `{"server_time": ..., "directives": []}` per [DEC-08](../../decisions/0008-api-conventions.md).
- No audit entries and no loads of snapshot tables. One cheap write per request.

### Acceptance criteria

- [ ] Heartbeat from a host in `stale` or `offline` returns it to `online` and records the transition
- [ ] Agent-reported time never affects `last_seen_at` or liveness (spec with a skewed clock)
- [ ] Heartbeat p95 stays under 200 ms with the [P1-O04](p1-verify.md) simulator at 50 hosts and a large snapshot table
- [ ] Heartbeats from a `pending`, `revoked`, or `retired` host are refused

## P1-S09: Liveness evaluation job, thresholds, and status history

### Scope

- `Setting` model (typed key/value with defaults) holding the online and stale thresholds (defaults 3 and 15 minutes) with validation that online is less than stale. A small settings form in the dashboard lets the operator change them; changes are audited ([P1-S03](p1-hosts.md)).
- `host_status_events` table (host, from, to, occurred at, reason), separate from the audit log.
- Recurring Solid Queue job (at least once per minute) that evaluates every active host from `last_seen_at` and writes events only when status changes. Idempotent and safe to run concurrently or twice.
- Status of hosts that are not `active` is not evaluated (they show their enrollment state).
- Hosts that have never sent a heartbeat stay out of `online` and are shown as awaiting first contact rather than offline.

### Acceptance criteria

- [ ] With a stopped heartbeat, a host moves online, then stale, then offline at the configured thresholds (spec using a controllable clock)
- [ ] Changing thresholds takes effect on the next run
- [ ] Re-running the job without changes writes no events
- [ ] Every transition has a history row with timestamps in server time
