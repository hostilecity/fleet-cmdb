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
- Delivered as `Advisories::ManualRefresh` (`cmdb/app/services/advisories/manual_refresh.rb`) and the table `advisory_refresh_attempts` (`cmdb/README.md`, "Advisory data"). The dashboard view is [P2-D06](p2-dash-fleet.md).
  - **Operation.** `request!(actor:, now:)` returns a `Result` (`accepted?`, `attempt`, `next_allowed_at`). Accepted, it records a manual attempt, audits `advisory.refresh_requested`, and enqueues `AdvisoryFeedRefreshJob` with the attempt's id after commit. Refused, it audits `advisory.refresh_refused` with `next_allowed_at` and writes nothing else. It raises `NotConfigured`, recording nothing, when `FLEET_ADVISORY_FEED_URL` is empty. `next_allowed_at(now:)` (nil when a refresh is allowed now) and `last_attempt` are for the button.
  - **Attempts.** A row records when each refresh started: manual at the request, a scheduled run on its first execution (not on retries, which are the same refresh), and `bin/rails advisories:refresh` as `task`. The cool-down runs from the newest of any kind. Retention prunes rows past the retention window.
  - **Concurrency.** The check and the insert run under a transaction-scoped PostgreSQL advisory lock, which the schedule and the task take too, for the moment of their insert only. An advisory lock rather than a row lock, since there is no row before the first refresh; rather than a unique constraint, since a time window is not a unique value. `spec/services/advisories/manual_refresh_concurrency_spec.rb` starts two requests at once and checks that one job is enqueued.
  - **Attribution.** The import a manual refresh leads to (succeeded, not modified, or failed) is stored and audited with that operator, so the imports list can say who refreshed. The schedule and the task stay the system.
  - **Configuration.** `FLEET_ADVISORY_REFRESH_COOLDOWN` is a whole number of seconds, at least 1 (empty means the default, 300). Any other value stops the server at boot with an error naming the setting, rather than falling back silently.

### Acceptance criteria

- [ ] A second manual refresh within the cool-down is refused with the time it is next allowed, and starts nothing
- [ ] Two concurrent manual refreshes start exactly one job (checked with a concurrency spec)
- [ ] The scheduled refresh and the rake task are not blocked by a manual one, and the next manual refresh waits for the cool-down after a scheduled one
- [ ] An accepted and a refused refresh are both audited with the operator as actor
