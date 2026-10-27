# P1-DASH-FLEET: Dashboard: mockups, fleet list, host detail, live status

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-D01: Phase 1 dashboard mockups (fleet list, host detail, enrollment, audit, settings)

### Context

The README reserves `docs/mockups/` for design before implementation, as with the owner's other projects. Settling the layout first avoids reworking views after the data is wired up.

### Scope

Static HTML mockups (no backend) in `docs/mockups/phase-1/`:

- Sign-in with Google and the not-allowlisted rejection page
- Fleet list: counts by status, search, tag and status filters, sortable columns, all liveness states, pending and revoked hosts
- Host detail: current inventory, inventory history with changed-field highlighting, credential and enrollment state, status history, audit entries, the clone-detection warning
- Create host and one-time token display (including the copy-once warning)
- Revoke, re-enroll, and retire confirmation dialogs
- Fleet-wide audit log page
- Settings (liveness thresholds)
- Empty states and error states (validation in place)

### Acceptance criteria

- [ ] Owner has reviewed and approved the mockups in the PR
- [ ] Every Phase 1 dashboard requirement in FR-1.5 is represented
- [ ] No real hostnames, addresses, or credentials appear in mockups

## P1-D02: Dashboard shell and fleet list

### Scope

- Application layout, navigation, signed-in operator, flash messages, consistent error and empty states (following the approved mockups).
- Fleet list of active hosts: name, hostname, tags, operating system, agent version, liveness status, last seen.
- Counts by status at the top (active hosts by liveness), with pending and revoked counts shown separately.
- Sort by any column, search by name and hostname, filter by tag and by status. State held in query parameters so views are linkable.
- Avoids N+1 queries; verified by a query-count spec.
- Plain server-rendered HTML first; live updates are added in [P1-D05](p1-dash-fleet.md).
- Settings page (moved here from [P1-S09](p1-heartbeat.md) so it follows the approved settings mockup): the online and stale liveness thresholds, saved with `Setting.update_liveness_thresholds!`, which validates them and audits the change. Errors are shown in place (FR-S.4).

### Acceptance criteria

- [ ] Sorting, searching, and each filter work and compose (specs)
- [ ] Retired hosts do not appear and are not counted
- [ ] Fleet list renders in under 2 seconds with 50 hosts ([P1-O04](p1-verify.md) confirms)
- [ ] All agent-supplied text is escaped (see [P1-S12](p1-operability.md))
- [ ] The settings page changes the liveness thresholds, rejects invalid values in place, and each change appears in the audit log

## P1-D03: Host detail view with inventory history and field-level diff

### Scope

- Current inventory (every required field from FR-1.3), with null fields displayed as unavailable together with their collection warnings.
- Inventory history: the list of snapshots with timestamps, and for each snapshot the fields that changed from the previous one highlighted (old value to new value).
- Enrollment state, credential state (active, revoked, never issued), token expiry if pending, the machine identifier mismatch warning.
- Status history from `host_status_events` (when the host went stale or offline and returned).
- The host's own audit entries (read-only).
- Pending, revoked, and retired hosts show their enrollment state instead of liveness.

### Acceptance criteria

- [ ] Changing a stable field on the VM produces a visibly highlighted change in the history
- [ ] The page matches `hostnamectl`, memory, and disk figures read on the VM (manual check recorded for AC-1.3)
- [ ] Status history shows when the host went offline and returned
- [ ] Hostile strings render escaped

## P1-D05: Live status updates without page reload

### Scope

- When a host's liveness status changes, the fleet list row, the status counts, and the host detail header update in place within 30 seconds, without a manual reload (Turbo Streams over Solid Cable, or polling if [DEC-02](../../decisions/0002-server-stack.md) chose that).
- Broadcast after the transaction commits so clients never see uncommitted state.
- Graceful behaviour when the connection drops: indicate the page may be stale and recover on reconnect.
- Only authenticated operators can subscribe.

### Acceptance criteria

- [ ] A status transition appears in an open browser within 30 seconds (system test or recorded manual check)
- [ ] Unauthenticated subscription attempts are rejected
- [ ] The counts and the row update together
