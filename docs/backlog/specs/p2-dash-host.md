# P2-DASH-HOST: Dashboard: host configuration, packages, and vulnerabilities

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-D01: Phase 2 dashboard mockups (config, packages, vulnerabilities, compliance, rules)

### Scope

Static HTML mockups in `docs/mockups/phase-2/`:

- Host detail tabs: configuration (facts, CIS results, snapshot diff, request-fresh-report button), packages (current set, snapshot diff), vulnerabilities (open and resolved)
- Fleet compliance view with pass rate and severity counts
- Rules management: list, view, edit, enable and disable, version history, import
- Advisory data sources and freshness indicator
- States for unreadable facts, not applicable, not evaluated, unsupported package manager, and no advisory data

### Acceptance criteria

- [ ] Owner has approved the mockups in the PR
- [ ] Every item in FR-2.5 is represented
- [ ] Wording uses "CIS-aligned", not "CIS compliant" ([DEC-10](../../decisions/0010-cis-rules.md))

## P2-D02: Host configuration view: facts, CIS results, snapshot diff

### Scope

- Latest config facts grouped by area, with unreadable and unsupported facts shown with their reasons.
- CIS results per rule (pass, fail, not applicable, not readable, not evaluated), filterable, with severity, observed value, and remediation text; per-host summary; result change history.
- Snapshot picker and diff between any two config snapshots.
- "Request fresh report" button using [P2-S03](p2-config-reports.md), showing outstanding state.
- Everything agent-derived is escaped.
- Delivered as `GET /hosts/:id/config` and `GET /hosts/:id/config/compare?from=&to=` (snapshot ids; by default the latest against the one before it), `HostConfigsController`, with the host header, summary tiles (`HostSummary`), and tab bar shared by every host tab (`HostTab`, `hosts/_header`), as the approved mockups and owner decisions Q1 to Q7 on the P2-D01 review say. The pass rate is passed / (passed + failed + not readable) (`CisCompliance::Summary#pass_rate`, Q3). Checks open on "Needs attention" (fail and not readable, Q4), grouped by the area of the fact they inspect (`ConfigArea`); facts show the ones a rule inspects or that are not OK, `?facts=all` for all. The cause of each result change (new config report with the fact before and after, rule edited with its editor, enabled, disabled) is worked out by `CisResultHistory` from the change before it, since a change does not record why its evaluation ran. The comparison lists result changes produced from the snapshots in the range as the effect of each changed, added, or removed fact, joining a rule's report changes only while no rule edit, enable, or disable comes between them; those rule changes are listed apart. A change of reason alone (unreadable for another reason) is shown with the state changes. The pickers offer every snapshot kept, with the newest 25 labelled by how many facts changed. The pickers are labelled "From" and "To" because Swap compares newer to older. The tab's request button asks for a config report only; its states (ready, pending before and after delivery, rate limited until a time, answered, expired, host cannot be asked) follow report-requests.html, and a rate-limited button refreshes the page when the limit ends (the `refresh-after` Stimulus controller, timed by the server's clock). An answered or expired outcome is shown for an hour after it ended.

### Acceptance criteria

- [ ] A changed SSH setting shows in the diff and flips the matching rule result (AC-2.1)
- [ ] Unreadable facts show their reason in the facts list and in dependent rule results (AC-2.5)
- [ ] The request button shows pending state and is rate limited

## P2-D03: Host packages view and snapshot diff

### Scope

- Current package set with search, sort, and a count; shows the package manager and the source package.
- Snapshot picker and diff showing installs, removals, and version changes.
- Explicit state for an unsupported package manager.
- Pagination or virtual rendering so a 3,000-package list stays fast.
- Delivered as `GET /hosts/:id/packages` and `GET /hosts/:id/packages/compare?from=&to=&kind=` (snapshot ids), `HostPackagesController`, under the shared host header, summary, and tabs. The list is `HostPackageList`: server-side search of the package and source package name, architecture and "open findings only" filters, sort by name, version, or source package, and pages of 50, all in the URL (owner decision Q15); a page is a fixed number of queries whatever the package count. Version sorts as text, since dpkg's order is not available in SQL; the diff, which uses dpkg's order (`PackageDiff`), says which way a version moved. Each row shows its open findings (count, and whether one was reopened). An unsupported package manager is said so in the tab, the tab's count, the summary tile, and the snapshot list, and a pair with an unsupported side has no diff. An unreadable package database (P2-S08, owner decision) is said so in a notice with the agent's reason and the last readable report's time, the tab's count ("Unreadable" when no list was ever read), the summary tile, and the snapshot list; the kept list is still shown, and the diff of an unreadable snapshot is not available, while the snapshot after it is compared with the one before it. The comparison shows installed, removed, upgraded, downgraded, cannot compare, source changed (the same version with another source package), and equivalent version (a version dpkg treats as equal that is spelled differently, such as `1.0` and `0:1.0`; its own counter and chip, only when there is one, a deviation from the mockup), and "Skipped / incomplete" (a package that was installed and is named in the later snapshot's skipped list, with the agent's reason, never shown as removed) in its own row, counter and filter that appear only when something was skipped, a deviation from the mockup (owner decision), filterable by kind; the mockup's optional Findings column (the findings each change opened or resolved) is left out, as the note on host-packages-diff.html allows. The oldest snapshot listed is labelled "Oldest package snapshot kept" ("No earlier snapshot kept"), not a first report, since Retention prunes old snapshots. The tab lists the latest 10 snapshots with their diffs; older ones are picked on the comparison page, whose pickers offer every snapshot kept.

### Acceptance criteria

- [ ] The list matches the VM's package manager listing (manual check recorded for AC-2.3)
- [ ] Diff correctly shows an install, a removal, and an upgrade
- [ ] Page loads quickly with a 3,000-package host

## P2-D04: Host vulnerabilities view

### Scope

- Open and resolved findings per host, grouped by package with the advisories nested under it (the package row shows the worst severity and the number of findings), filterable by severity and state, with installed version, fixed version, advisory id, and a link to the source advisory (only `http` and `https` links, opened with `rel="noopener noreferrer"`).
- A per-package view of the findings for one package.
- Clear "not evaluated" states with reasons (unmapped distribution, no advisory data imported, unsupported package manager) instead of an empty list.
- Advisory data freshness shown when [P2-S13](p2-vulns.md) is in use.

### Acceptance criteria

- [ ] Findings can be filtered by severity and state
- [ ] A host that cannot be evaluated says so and why
- [ ] A resolved finding shows when and how it resolved
