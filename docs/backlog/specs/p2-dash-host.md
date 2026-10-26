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

### Acceptance criteria

- [ ] The list matches the VM's package manager listing (manual check recorded for AC-2.3)
- [ ] Diff correctly shows an install, a removal, and an upgrade
- [ ] Page loads quickly with a 3,000-package host

## P2-D04: Host vulnerabilities view

### Scope

- Open and resolved findings per host, filterable by severity and state, with installed version, fixed version, advisory id, and a link to the source advisory (only `http` and `https` links, opened with `rel="noopener noreferrer"`).
- A per-package view of the findings for one package.
- Clear "not evaluated" states with reasons (unmapped distribution, no advisory data imported, unsupported package manager) instead of an empty list.
- Advisory data freshness shown when [P2-S13](p2-vulns.md) is in use.

### Acceptance criteria

- [ ] Findings can be filtered by severity and state
- [ ] A host that cannot be evaluated says so and why
- [ ] A resolved finding shows when and how it resolved
