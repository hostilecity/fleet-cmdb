# VT-SCORES: Exposure score and work remaining on the summaries, the fleet list, and the summary tiles

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed). The score, tier, and work definitions are the epic's VT-M3 and VT-M4. Drawn in [fleet.html](../../mockups/vuln-triage/fleet.html) and [tiles.html](../../mockups/vuln-triage/tiles.html).

## VT-S07: Score, tier, and work on the summaries

### Scope

- `host_compliance_summaries` gains, recounted by the existing triggers (ADR 0026): `exposure_points` (the published table, each advisory once per host in its worst bucket, KEV doubled outside Ignorable), `exposure_tier` (0 to 4), `vuln_kev_open` (KEV advisories outside Ignorable), `vuln_attention_undecided`, `reboot_pending` (from the inventory, VT-A01), `work_items` (generated: `vuln_fix_packages` plus 1 when a reboot is pending), and the streak timestamps `fixable_critical_since` and `no_fixable_critical_since`.
- The recount groups the host's open findings by advisory to count each once; measure it at 450 and 6,000 findings per host and at 100,000 hosts with `bin/benchmark`, against ADR 0026's figures.
- Indexes for the sorts, partial on active hosts with the name tie-break, as ADR 0026: points descending, work descending.
- The breakdown on the host tab ("why N points") is computed for one host on view.

### Acceptance criteria

- [ ] A host's points equal the table applied to its findings (spec over every bucket and severity, KEV doubled, one advisory on two packages counted once)
- [ ] `compliance_summaries:check` covers the new columns and finds no drift

## VT-D06: Fleet list columns and summary tiles

### Scope

- Fleet list: the "Open vulnerabilities" column becomes **Exposure** (tier word, points, how many need attention) and **Work** (upgrades, a pending reboot, 30-day progress), both sortable by keyset; a vulnerabilities filter (known exploited, needs attention, has a fix, nothing to install, not evaluated). Not evaluated and not tracked hosts read as today, never 0 points.
- Fleet compliance panel: one more line with the bucket totals and upgrades.
- Host summary tiles: "Open vulnerabilities" becomes **Vulnerability exposure** and **Work remaining**; the Packages tile moves to the tab count, which already shows it (epic question 15 for the fleet list).
- Compliance page: one line of bucket totals under the severity strip, each a filter (`?bucket=`).
- The honesty rules of epic VT-M5 for every badge and streak shown here.

### Acceptance criteria

- [ ] Sorting the fleet list by Exposure or Work reads one page of summaries in a fixed number of statements at any fleet size
- [ ] A not evaluated or stale host never shows 0 points, "Nothing to install", or a streak
