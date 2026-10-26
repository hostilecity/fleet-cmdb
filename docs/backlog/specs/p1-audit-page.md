# P1-AUDIT-PAGE: Read-only fleet-wide audit log page

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Context

The audit log foundation ([P1-S03](p1-hosts.md)) was delivered in P1-HOSTS. That issue's page was split out because it needs operator sign-in ([P1-S01](p1-access.md)). Without sign-in the page would expose the audit trail to anyone who can reach the dashboard (FR-S.4, NFR-1). It also needs the approved audit page mockup from [P1-D01](p1-dash-fleet.md). Per-host entries on the host page stay in [P1-D03](p1-dash-fleet.md).

## Scope

- **Route:** a read-only page at `GET /audit`, on the dashboard hostname only and behind operator sign-in, like every dashboard route ([P1-ACCESS](p1-access.md)). It has no create, update, or destroy routes.
- **Layout:** built from the approved P1-D01 audit mockup in `docs/mockups/phase-1/`.
- **Entries:** shown newest first, with the time, the actor (operator email, host name, or "system"), the action, the target (linked to the host when it is one), and the before and after values. Read through `AuditEntry` only, never written.
- **Filters:**
  - by actor type and actor
  - by action, from `Audit::Actions::ALL`
  - by target
  - by date range on `occurred_at`

  Filters are carried in query parameters, so a filtered view can be bookmarked.
- **Pagination:** keyset pagination on `(occurred_at, id)`, so the page stays fast as the log grows (audit entries are never pruned, FR-S.3). Use the existing `index_audit_entries_on_*` indexes.
- **Escaping:** all values are escaped when rendered (NFR-1). Before and after values come from operator and agent input.

## Acceptance criteria

- [ ] A signed-in operator sees entries newest first and can filter by actor, action, target, and date range, with pagination (request specs)
- [ ] Anonymous requests are redirected to sign-in, and the P1-ACCESS route-enumeration spec covers `/audit`
- [ ] The page offers no way to create, edit, or delete an entry, and markup in recorded values is rendered escaped
