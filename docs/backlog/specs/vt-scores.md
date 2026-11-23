# VT-SCORES: Exposure tier and points and work remaining on the summaries, the fleet list, and the summary tiles

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (approved by the owner, 2026-11-19). The tier, points, and work definitions are the epic's VT-M3 and VT-M4. Drawn in [fleet.html](../../mockups/vuln-triage/fleet.html) and [tiles.html](../../mockups/vuln-triage/tiles.html).

## VT-S07: Tier, points, and work on the summaries

### Scope

- `host_compliance_summaries` gains, recounted by the existing triggers (ADR 0026): `exposure_tier` (0 to 4), `exposure_points` (the published table, each advisory once per host in its worst bucket, "by a control" rows for O1, KEV doubled outside Ignorable, from the findings' stored `kev` flag so a KEV change always recounts, S2), `vuln_attention_undecided` (Needs attention advisories with no accepted risk: VT-OVERRIDES' accepted risks are not due, and counting them on the summaries is #298), `work_items` (source packages to upgrade by F1 or F2, plus 1 for a K2 kernel install, plus 1 for a pending reboot: K1, or the agent's reboot flag), and the run timestamps `fixable_critical_since` and `no_fixable_critical_since`. Whether KEV or EPSS was ever imported, and whether it is stale, is not a column: it is read once per page and shown as a qualifier (B1), so a freshness change rewrites no summary.
- The recount groups the host's open findings by advisory to count each once; measure it at about 4,000 findings per host and at 100,000 hosts with `bin/benchmark`, against ADR 0026's figures.
- Indexes for the sorts, partial on active hosts with the name tie-break: **tier descending, then points descending** (S6, so one known-exploited host always ranks above any number of medium findings), and work items descending.
- The tier and points of a host are computed with whatever KEV and EPSS data is stored; when a source is stale or was never imported, the page shows the tier with "not re-checked against KEV since ..." or "not checked against KEV", never a lower tier.
- Adds the score breakdown ("why N points") and the run badge to the host tab (VT-D04).

### Acceptance criteria

- [ ] A host's points equal the table applied to its findings (spec over every bucket and severity, a control, an acceptance, KEV doubled, one advisory on two packages counted once), and a KEV change on a Fix available finding updates them
- [ ] `compliance_summaries:check` covers the new columns and finds no drift

## VT-D06: Fleet list columns and summary tiles

### Scope

- Fleet list: the "Open vulnerabilities" column becomes **Exposure** (tier word, points, how many need attention) and **Work** (work items: upgrades, a new kernel, a reboot), sorted by keyset (Exposure: tier, then points). The hostname and tags move under the name, so the table fits the page at 1,280 px (N6; measured in headless Chrome). Progress is not on the fleet list (it is a 30-day window the summaries cannot keep; host tab and tiles only, S5c). A vulnerabilities filter (known exploited, needs attention, has a fix, nothing to install, not evaluated). Not evaluated and not tracked hosts read as today, never 0 points.
- Fleet compliance panel: one more line with the bucket totals and work items.
- Host summary tiles: "Open vulnerabilities" becomes **Vulnerability exposure** (tier, points) and **Work remaining** (work items and 30-day progress, read for that host); the Packages tile is dropped, since the Packages tab shows the count (epic decision 18).
- Compliance page: one line of bucket totals under the severity strip, each a filter (`?bucket=`).
- The honesty rules of epic VT-M5 for every badge and run shown here, including the wording during a run's grace.

### Acceptance criteria

- [ ] Sorting the fleet list by Exposure (tier, then points) or Work reads one page of summaries in a fixed number of statements at any fleet size
- [ ] A not evaluated or stale host never shows 0 points, "Nothing to install", or a run badge, and a stale or never-imported KEV source never shows a lower tier
