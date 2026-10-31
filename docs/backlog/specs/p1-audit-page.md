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

## Decisions from the mockup review

The owner answered the open questions on the reworked mockup (PR #66):

1. **Onboarding entries and their host.** Approvals and rejections target the request. The page links a request to the host it became, and filtering by a host includes that request's entries. Requests are pruned a day after they expire, so the link comes from the log itself: the host's "Enrolled" entry records `onboarding_request_id`, and a re-enrollment approval records `host_id`. Two partial expression indexes on `audit_entries` serve these lookups. Substring matching of host names, hostnames, and operator emails (the target and actor filters, and the fleet search) is served by `pg_trgm` GIN indexes, so it does not read the whole table at fleet scale.
2. **Text or id.** The target filter takes typed text and matches host name or hostname (case-insensitive substring, as in the fleet search), retired hosts included. The host page's "All entries for this host" link filters by exact host id (`host_id=`).
3. **Target scope.** The target filter covers hosts only.
4. **Phone layout.** The table scrolls sideways inside its frame, like the other tables.
5. **Sign-ins.** "Operator signed in" stays in the default view; a one-click "Hide sign-ins" link (`hide_sign_ins=1`) hides it while no action is chosen.
6. **Request id.** Each entry shows its request id, to match it to a server log line.
7. **Paging.** 50 entries per page; readable keyset cursors `before=` and `after=` with `<occurred_at in UTC to the microsecond>,<id>`. A malformed or tampered cursor is ignored with a notice, and the newest page is shown. An invalid date is shown as an error in place, with no entries listed.

## Acceptance criteria

- [ ] A signed-in operator sees entries newest first and can filter by actor, action, target, and date range, with pagination (request specs)
- [ ] Anonymous requests are redirected to sign-in, and the P1-ACCESS route-enumeration spec covers `/audit`
- [ ] The page offers no way to create, edit, or delete an entry, and markup in recorded values is rendered escaped
