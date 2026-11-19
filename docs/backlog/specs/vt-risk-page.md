# VT-RISK-PAGE: Fleet risk overview with burn-down, leaderboards, quick wins, and runs

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed), not in the recommended first cut (epic question 21). There is no fleet-wide vulnerabilities page today (#253); #252's fleet-wide by-package page stays deferred (epic question 22). Drawn in [risk-overview.html](../../mockups/vuln-triage/risk-overview.html).

## VT-S08: Daily totals and quick wins

### Scope

- `vulnerability_daily_totals`: per day, bucket, and severity, the findings and hosts, plus Needs attention findings with an accepted risk and Low risk findings under a control; written once a day just after midnight UTC by summing active summaries, idempotent per day; kept `FLEET_DAILY_TOTALS_DAYS` (400). Days on which an advisory, triage, KEV, or EPSS import changed buckets are marked from the import records.
- `vulnerability_quick_wins`, built **once a day** (S12), labelled "as of": per ecosystem, source package, and the highest fixed version among its Fix available findings, the findings it would clear and the hosts. ADR 0028 measured whole package sets as 78 to 96% distinct, so "chunks, then sets, then hosts" costs about candidates times hosts at scale. Instead it reads the open findings with `bucket = fix` through a partial index, grouped by advisory and package and mapped to source packages through `advisory_packages`: about hosts times Fix available findings per host (78 on the example host, so about 78 million index entries at a million hosts), one scan a day. Top 50 kept. Also "reboot N hosts" (summaries with a pending reboot), "install the new kernel on N hosts" (K2), and the "tidy-up: remove kernels that are not running" row from rule I1 counts, which says it changes no exposure.
- Measure both jobs at 100,000 hosts with about 4,000 open findings per host using `bin/benchmark`, and record them here; if quick wins exceed a few minutes, keep fewer candidates or move the scan to the replica (ADR 0031).

### Acceptance criteria

- [ ] The daily totals for a day equal the sum of that day's summaries, and running the job twice changes nothing
- [ ] Quick wins are built once a day within a time measured and recorded at 100,000 hosts with about 4,000 findings each

## VT-D07: The Risk page

### Scope

- `GET /risk`, **Risk** in the top bar after Compliance (epic question 20): the fleet bucket strip, hosts per tier, the two burn-down charts (SVG with title, description, and a table), most exposed hosts (tier, then points) and most work (work items), top 5 each from the summary indexes, quick wins, hosts with no fixable critical and the longest run, and decisions due (VT-OVERRIDES).
- No progress figures (they are per host; S5c). Every count says how many hosts were evaluated; staleness qualifiers as on the host tab; the honesty rules of epic VT-M5; no ranking of people.
- Live refresh as the fleet pages, with a fixed number of statements per view.

### Acceptance criteria

- [ ] The page loads in under 2 s at 50 hosts and in a fixed number of statements at 100,000 (measured)
- [ ] The charts have text equivalents, the page passes axe-core with no violations, and accepted risks are drawn inside Needs attention, not as handled
