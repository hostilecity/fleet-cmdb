# VT-RISK-PAGE: Fleet risk overview with burn-down, leaderboards, quick wins, and streaks

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed). There is no fleet-wide vulnerabilities page today (#253; #252 question 5). Drawn in [risk-overview.html](../../mockups/vuln-triage/risk-overview.html).

## VT-S08: Daily totals and quick wins

### Scope

- `vulnerability_daily_totals`: per day, bucket, and severity, the findings and hosts, plus findings in Low risk by a decision; written once a day just after midnight UTC by summing active summaries (one pass over the narrow table), idempotent per day; kept `FLEET_DAILY_TOTALS_DAYS` (400). Days on which an advisory, triage, KEV, or EPSS import changed buckets are marked from the import records.
- `vulnerability_quick_wins`: rebuilt after each matching or triage run finishes, and daily. Per ecosystem, source package, and the highest fixed version among its fixable verdicts: findings it would clear and hosts, from `chunk_matches` grouped per chunk, the sets holding those chunks (GIN on `package_sets.chunk_ids`), and the hosts on those sets (`host_vulnerability_evaluations.package_set_id`). Top 50 kept with the time it was built. Approximate by design (host-specific rules and decisions are ignored) and says so. Also "reboot N hosts" from `reboot_pending` and the "tidy-up: remove old kernels" row from rule I1 counts.
- Measure both jobs at 100,000 hosts with `bin/benchmark` and record them here.

### Acceptance criteria

- [ ] The daily totals for a day equal the sum of that day's summaries, and running the job twice changes nothing
- [ ] Quick wins are built from chunks and sets, not per host, within a time measured and recorded at 100,000 hosts

## VT-D07: The Risk page

### Scope

- `GET /risk`, **Risk** in the top bar after Compliance (epic question 16): the fleet bucket strip (one sum over summaries), hosts per tier, the two burn-down charts (SVG with title, description, and a table of the numbers), most exposed hosts and most work (top 5 each, from the summary indexes, linking to the fleet list sorted), quick wins, hosts with no fixable critical with the longest streak, and decisions due.
- Every count says how many hosts were evaluated and links to the not evaluated ones; the honesty rules of epic VT-M5 throughout; no ranking of people.
- Live refresh as the fleet pages (Turbo morph), with a fixed number of statements per view.

### Acceptance criteria

- [ ] The page loads in under 2 s at 50 hosts and in a fixed number of statements at 100,000 (measured)
- [ ] The charts have text equivalents and the page passes axe-core with no violations
