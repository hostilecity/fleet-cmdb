# P2-DASH-FLEET: Dashboard: fleet compliance and rule management

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-D05: Fleet compliance view and fleet-wide severity counts

### Scope

- A table of every active host with its CIS pass rate, open CIS failures by severity, and open vulnerability findings by severity; sortable and filterable by tag.
- Fleet-wide counts of open findings by severity at the top, and a link or summary from the Phase 1 fleet list.
- Hosts that are not evaluated are visibly distinct from hosts with no findings.
- Efficient queries (no N+1, aggregated in the database).

### Acceptance criteria

- [ ] Loads in under 2 seconds with 50 hosts ([P2-S12](p2-accept.md))
- [ ] Counts match the underlying findings and results (spec)
- [ ] "Not evaluated" and "zero findings" are never shown the same way

## P2-D06: Rules and data sources management UI

### Scope

- Rules: list with filters, rule detail with version history, add one rule from a form (a single comparison; a rule with several conditions comes in by importing a file), edit the condition and metadata with validation in place, a preview of which hosts would change result before an edit is saved (uses the dry run in [P2-S06](p2-cis-engine.md)), enable and disable (with confirmation), upload a rules file with a preview of what would change before applying.
- Advisory data: show sources, last import, counts per ecosystem, upload an advisory file, trigger a manual feed refresh if [P2-S13](p2-vulns.md) exists.
- Every change audited with the operator as actor; edits show before and after.

### Acceptance criteria

- [ ] AC-2.2: editing a rule's expected value in the UI re-evaluates and changes results with no agent contact
- [ ] Invalid edits are rejected with errors in place
- [ ] Adding a rule creates version 1 through the same checks as import, re-evaluates every host, and is audited
- [ ] The edit preview lists the hosts whose result would change, with before and after, and writes nothing
- [ ] The import preview lists adds, changes, and unchanged rules before anything is written
