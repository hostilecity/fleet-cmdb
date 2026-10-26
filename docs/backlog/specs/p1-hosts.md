# P1-HOSTS: Host records, enrollment states, and audit log

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-S02: Host model, tags, and enrollment state machine

### Scope

- `hosts` table: display name, hostname, description, notes, tags, enrollment state, first seen, last seen, agent version, agent schema version, liveness status (the column; evaluation lives in [P1-S09](p1-heartbeat.md)).
- Enrollment states `pending`, `active`, `revoked`, `retired`, with the transitions table from FR-1.1 implemented as explicit model methods. Invalid transitions raise and are never silently ignored; `retired` is terminal.
- Tags: normalised (lowercase, trimmed, length and count limits) and filterable with an index.
- Validation of every operator-editable field (length, format).
- Scopes for the fleet views: active hosts, hosts by tag, hosts by liveness status.
- Retiring is a soft state; no hard delete path exists.

### Acceptance criteria

- [ ] Every row in the FR-1.1 transition table has a spec; every other transition has a spec proving it is rejected
- [ ] Retired hosts are excluded from the active fleet scope
- [ ] Tag normalisation and filtering are covered by specs

## P1-S03: Audit log foundation

### Scope

- `audit_entries` table: actor type and id (operator, agent host, or system), action, target type and id, server-side `occurred_at`, before and after values (JSON), request id.
- A single entry point (for example `Audit.record(actor:, action:, target:, changes:)`) that writes inside the same database transaction as the change it describes, so a change cannot exist without its entry or vice versa.
- Append-only: no update or destroy path in the application. Evaluate a database-level guard (trigger or revoked privileges); record the outcome in the PR.
- A scrubber ensures credentials, tokens, and digests can never be placed in before/after values.
- Action names defined in one place as constants (host created, enrolled, credential revoked, host edited, host retired, token issued, and so on). Later phases add rule changes and task actions.
- The read-only fleet-wide audit log page moved to [P1-AUDIT-PAGE](p1-audit-page.md), because it needs operator sign-in first. Per-host entries on the host page are in [P1-D03](p1-dash-fleet.md).

### Acceptance criteria

- [ ] No code path updates or deletes an audit entry (spec plus, if adopted, a database-level test)
- [ ] A failed transaction leaves no audit entry, and a committed change always has one
- [ ] Attempting to log a field named like a secret raises in test and is filtered in production
