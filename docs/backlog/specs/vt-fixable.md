# VT-FIXABLE: Store whether each open finding has a fix, count it, and filter by it

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed). This slice **folds in #252**: its definition of "fix available" (the advisory names a fixed version for the host's release, the range the installed version is in) and its filter, built so that VT-BUCKETS later only adds buckets beside it. It gives the owner the first visible answer ("what is fixable") before any new data source. The flag says only whether the advisory data names a fix for the release; kernel fixes (K1, K2) and Debian's own fixed version (F2) are VT-BUCKETS' rules, so until then a running kernel's fix shows here as "Fix available" on its package row, and the tab says a kernel fix needs a new package and a reboot.

## VT-S01: A fix flag on the open finding, kept by the matcher, counted by the summaries

### Scope

- `vulnerability_findings.fixable boolean` (null while resolved), written by the host's transitions in the same statements that write an open finding's moved fix today (ADR 0028, "As built", item 6): when a finding opens or reopens, and whenever its verdict's fixed version appears, moves, or disappears. A host whose flags do not change writes nothing.
- An advisory import that moves fixes runs the existing `EvaluationRun::Advisories`, whose transitions write the flag; no separate recount is needed (this is #252's option (a)).
- `host_compliance_summaries` gains `vuln_fixable` (open and reopened findings with a fix) and `vuln_fix_packages` (distinct package and architecture among them), recounted by the existing triggers (ADR 0026); `bin/rails compliance_summaries:check` and `rebuild` cover them.
- `bin/benchmark explain` gains the recount with the flag at 100,000 hosts and about 4,000 open findings per host; record the before and after.

### Acceptance criteria

- [ ] After an import that adds a fixed version to an open finding's range, the finding's flag and its host's summary say it has a fix, with no change of state
- [ ] `compliance_summaries:check` finds no drift after matching, imports, and package reports in the suite

## VT-D02: The filter and the counts in the dashboard

### Scope

- Host Vulnerabilities tab: two chips beside the state chips, "Fix available N" and "No fix available N" (`?fix=available|none`), counted over the open list whatever the severity and text filters, as #252 section 4 proposes. Package rows count only the findings the filter keeps.
- Compliance page: the detail line "N with a fix" under each host's vulnerability counts, and a status filter "Has open findings with a fix" (`?fix=available`), combinable with `vuln=` to mean a finding of that severity with a fix (#252 question 8).
- Fleet list: the detail line "N with a fix (M packages)" under the open count. VT-SCORES later replaces the column.
- No change to any existing count, sort, or severity; not evaluated hosts are never counted as having a fix (#252 question 6).

### Acceptance criteria

- [ ] On the host tab, "Fix available" and "No fix available" add up to the open list's count, and the filter is kept in the URL
- [ ] The Compliance page's "with a fix" numbers equal the host tabs' and are read from the summaries in a fixed number of statements
