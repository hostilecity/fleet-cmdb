# P2-REFRESH-LIMIT: Cool-down for manual advisory feed refresh

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Added in the P2-D01 mockup review ([#113](https://github.com/hostilecity/fleet-cmdb/pull/113)): the owner wants "Refresh now" on the data sources page to have a cool-down like report requests ([P2-S03](p2-config-reports.md)), shown as a disabled button with the time left (`data-sources.html`).

## P2-S15: Cool-down for manual advisory feed refresh

### Scope

- A manual refresh (the dashboard button of [P2-D06](p2-dash-fleet.md); the scheduled job and `bin/rails advisories:refresh` are not limited) is refused when the last manual or scheduled refresh attempt started less than 5 minutes ago. The window is `FLEET_ADVISORY_REFRESH_COOLDOWN` seconds (default 300) and is enforced in the database, not in the page, so two operators cannot start two refreshes by clicking together.
- The refusal names the time at which a refresh is next allowed, in the response and in the audit log. A refused attempt writes no import, starts no job, and changes nothing else.
- The dashboard reads the same time to disable the button and say when it is available again, and shows the refusal if the page was stale.
- An accepted manual refresh is audited with the operator as actor and starts the same job as the schedule, so size limits, conditional requests, failures, and freshness work as in [P2-S13](p2-vulns.md).
- Documented in `cmdb/README.md`.

### Acceptance criteria

- [ ] A second manual refresh within the cool-down is refused with the time it is next allowed, and starts nothing
- [ ] Two concurrent manual refreshes start exactly one job (checked with a concurrency spec)
- [ ] The scheduled refresh and the rake task are not blocked by a manual one, and the next manual refresh waits for the cool-down after a scheduled one
- [ ] An accepted and a refused refresh are both audited with the operator as actor
