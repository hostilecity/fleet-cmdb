# VT-FIXABLE: Store whether each open finding has a fix, count it, and filter by it

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (approved by the owner, 2026-11-19). This slice **folds in #252**: its definition of "fix available" (the advisory names a fixed version for the host's release, the range the installed version is in) and its filter, built so that VT-BUCKETS later only adds buckets beside it. It gives the owner the first visible answer ("what is fixable") before any new data source. The flag says only whether the advisory data names a fix for the release; kernel fixes (K1, K2) and Debian's own fixed version (F2) are VT-BUCKETS' rules, so until then a running kernel's fix shows here as "Fix available" on its package row, and the tab says a kernel fix needs a new package and a reboot.

## VT-S01: A fix flag on the open finding, kept by the matcher, counted by the summaries

### Scope

- `vulnerability_findings.fixable boolean` (null while resolved), written by the host's transitions in the same statements that write an open finding's moved fix today (ADR 0028, "As built", item 6): when a finding opens or reopens, and whenever its verdict's fixed version appears, moves, or disappears. A host whose flags do not change writes nothing.
- An advisory import that moves fixes runs the existing `EvaluationRun::Advisories`, whose transitions write the flag; no separate recount is needed (this is #252's option (a)).
- `host_compliance_summaries` gains `vuln_fixable` (open and reopened findings with a fix) and `vuln_fix_packages` (distinct package and architecture among them), recounted by the existing triggers (ADR 0026); `bin/rails compliance_summaries:check` and `rebuild` cover them.
- `bin/benchmark explain` gains the recount with the flag at 100,000 hosts and about 4,000 open findings per host; record the before and after.

### Acceptance criteria

- [x] After an import that adds a fixed version to an open finding's range, the finding's flag and its host's summary say it has a fix, with no change of state (`spec/services/vulnerability_fix_flag_spec.rb`)
- [x] `compliance_summaries:check` finds no drift after matching, imports, and package reports in the suite (the same spec, and `spec/models/host_compliance_summary_spec.rb`)

## VT-D02: The filter and the counts in the dashboard

### Scope

- Host Vulnerabilities tab: two chips beside the state chips, "Fix available N" and "No fix available N" (`?fix=available|none`), counted over the open list whatever the severity and text filters, as #252 section 4 proposes. Package rows count only the findings the filter keeps.
- Compliance page: the detail line "N with a fix" under each host's vulnerability counts, and a status filter "Has open findings with a fix" (`?fix=available`), combinable with `vuln=` to mean a finding of that severity with a fix (#252 question 8).
- Fleet list: the detail line "N with a fix (M packages)" under the open count. VT-SCORES later replaces the column.
- No change to any existing count, sort, or severity; not evaluated hosts are never counted as having a fix (#252 question 6).

### Acceptance criteria

- [x] On the host tab, "Fix available" and "No fix available" add up to the open list's count, and the filter is kept in the URL (`spec/requests/host_vulnerabilities_spec.rb`)
- [x] The Compliance page's "with a fix" numbers equal the host tabs' and are read from the summaries in a fixed number of statements (`spec/models/fleet_compliance_spec.rb`, `spec/requests/compliance_spec.rb`; the page's statement count spec is unchanged)

## As built (#256)

- **The flag is a stored generated column**, `fixable = CASE WHEN state <> 'resolved' THEN last_fixed_version IS NOT NULL END`. The matcher already wrote `last_fixed_version` in the transitions named above (open, reopen, and an open finding's fix appearing, moving, or disappearing), so the flag is written in those statements by the database and cannot drift from the stored fix. Adding it rewrites `vulnerability_findings` once (NFR-5).
- **The tab reads the stored fix.** `VulnerabilityFinding.with_details` reads an active finding's fixed version from `last_fixed_version` instead of its live verdict, so "Fixed in", the package rows' "Fix for N of M", the chips, the Compliance page, and the fleet list always agree. Between an import committing and its run reaching a host, the host shows the fix it had (as its counts do); the run then writes both.
- **Summaries:** `vuln_fixable` and `vuln_fix_packages` as specified, plus `vuln_fix_severities` (a bit per severity with a fix: critical 1, high 2, medium 4, low 8, unknown 16), which `vuln=<severity>&fix=available` needs to mean "an open finding of that severity with a fix" (#252 question 8); two counts could not answer it. All three are zero for a host that is not evaluated (#252 question 6), in the counting function itself, so no reader can count it by mistake. The host tab still filters a not-evaluated host's kept findings by their stored flags, under its "earlier evaluation" notice.
- **Trigger:** `host_compliance_summaries_changed` v04 also notes an update whose flag changed; a fix moving from one version to another writes the finding but not the summary.
- **Live refresh:** a matching run counts an open finding whose fix or source moved as a change of what the host shows, so its pages refresh.
- **Host tab:** the chips are counted in the state chips' grouped query (`group(:state, :fixable)`), so the tab sends the same number of statements as before, with or without the filter. The chip of the current filter clears it; links keep the other filters and drop the cursors.
- **Compliance page:** the "N with a fix" line is under the host's name (with the "not evaluated now" line), not under the five severity cells, so the table keeps one row per host; it links to the host's tab with `?fix=available`. A line under the vulnerability strip gives the fleet's hosts and findings with a fix, linking to the filter, and the filter form has a "Fixes" select.
- **Benchmark:** `bin/benchmark seed --advisories-per-source 5` gives the template host 4,450 open findings (most with no fix); `bin/benchmark explain` has the recount, the Compliance filter, and the tab's filter as probes.

