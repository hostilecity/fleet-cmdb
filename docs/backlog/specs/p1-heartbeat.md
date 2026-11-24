# P1-HEARTBEAT: Heartbeat endpoint and liveness evaluation

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-S07: Heartbeat endpoint

### Scope

- `POST /api/v1/heartbeat` accepting host identity, agent version, agent uptime, and the agent's current time.
- Updates only `last_seen_at` (server time), agent version, agent schema version, and the agent-reported time (stored separately, never used for liveness). Sets `first_seen_at` on the first successful heartbeat.
- Storage (#192, [ADR 0029](../../decisions/0029-heartbeat-state-in-a-narrow-table.md)): `last_seen_at`, the liveness status, and the agent-reported time are in `host_liveness`, one narrow row per host that has sent a heartbeat, with no index but its key, so the heartbeat's update is heap-only (HOT). The agent version, schema version, task capabilities, and `first_seen_at` stay on `hosts` and are written only when they change, so a steady heartbeat does not write the `hosts` row.
- **The agent process** (#251). The optional `process` object carries the process's start (agent clock), systemd's `NRestarts` for `fleet-agent.service`, and how the process before it stopped (systemd's result, exit code, and exit status, from the record the unit's `ExecStopPost=` writes). It is stored on `hosts` (`agent_process_started_at`, `agent_restarts`, `agent_last_stop_*`) and written only when it changes: once per new process. Restarts are counted from `NRestarts`: a rise counts the difference, a fall (reset by a manual start, an update, or a boot) counts the new value, and the first value, an unread `null`, or an equal one counts none, so the count is a lower bound. Each counted restart is kept at the server's time, newest first, at most 32 (`agent_recent_restarts`, with `agent_restarted_at` the latest), and `agent_restart_loop_at` holds the (limit + 1)th newest. The agent's times are rounded to microseconds, as PostgreSQL stores them, so a time sent with nine digits does not make every heartbeat write. A heartbeat without the object, such as the installer's or an older agent's, changes nothing stored. A start later than the heartbeat's own `agent_time`, or an exit status that does not fit its code, is logged and ignored, and the heartbeat is still accepted. A heartbeat that counted restarts is broadcast to open pages and passed to `Rollouts.restarts_seen!` ([P1-UPDATES](p1-updates.md)). The host page shows the restarts in the window, systemd's count, and the last stop, with a notice and next step for a restart loop. The fleet list's "Restarted: more than N times in H hours" filter lists those hosts, from a partial index on `agent_restart_loop_at`, so its page reads only the hosts that loop. `bin/rails restart_loops:refresh` stores that column again after the limit is lowered. A steady heartbeat reads and writes nothing more.
- If the host was not `online`, it becomes `online` in the same transaction and a status history row is written ([P1-S09](p1-heartbeat.md) owns the table), so recovery shows immediately rather than after the next job run.
- Response: `{"server_time": ..., "directives": {}}` per [DEC-08](../../decisions/0008-api-conventions.md) as amended by [DEC-20](../../decisions/0020-named-heartbeat-directives.md): `directives` is an object keyed by directive name, empty until [P1-UPDATES](p1-updates.md) adds `intervals` and `agent_update`.
- No audit entries and no loads of snapshot tables. One cheap write per request.

### Acceptance criteria

- [ ] Heartbeat from a host in `stale` or `offline` returns it to `online` and records the transition
- [ ] Agent-reported time never affects `last_seen_at` or liveness (spec with a skewed clock)
- [ ] Heartbeat p95 stays under 200 ms with the [P1-O04](p1-verify.md) simulator at 50 hosts and a large snapshot table
- [ ] Heartbeats from a `pending`, `revoked`, or `retired` host are refused (a `pending` host still holding its old credential during re-enrollment gets `403 reenrollment_required` with `Fleet-Enrollment-State: pending`; revoked and retired hosts' credentials are revoked, so they get `401`)

## P1-S09: Liveness evaluation job, thresholds, and status history

### Scope

- `Setting` model (typed key/value with defaults) holding the online and stale thresholds (defaults 3 and 15 minutes) with validation that online is less than stale. Changes are audited ([P1-S03](p1-hosts.md)) and made with `bin/rails settings:liveness`. The dashboard settings form moved to [P1-DASH-FLEET](p1-dash-fleet.md), so it is built from the approved settings mockup.
- `host_status_events` table (host, from, to, occurred at, reason), separate from the audit log.
- Recurring Solid Queue job (at least once per minute) that evaluates every active host from `last_seen_at` and writes events only when status changes. It reads the narrow `host_liveness` table once per run, not `hosts`, and locks only the host rows it moves (#192). Idempotent and safe to run concurrently or twice. Runs are serialised by a session-level advisory lock, and transitions are written in transactions of at most 1,000 hosts, so a heartbeat never waits behind a fleet-wide transition (for example every host going offline after a server outage).
- Status of hosts that are not `active` is not evaluated (they show their enrollment state).
- Hosts that have never sent a heartbeat stay out of `online` and are shown as awaiting first contact rather than offline.

### Acceptance criteria

- [ ] With a stopped heartbeat, a host moves online, then stale, then offline at the configured thresholds (spec using a controllable clock)
- [ ] Changing thresholds takes effect on the next run
- [ ] Re-running the job without changes writes no events
- [ ] Every transition has a history row with timestamps in server time
