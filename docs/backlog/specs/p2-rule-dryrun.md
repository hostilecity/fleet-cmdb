# P2-RULE-DRYRUN: Dry run for an edited CIS rule

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Added in the P2-D01 mockup review ([#113](https://github.com/hostilecity/fleet-cmdb/pull/113)): the owner wants the rule edit page to show which hosts would change result before the edit is saved ([P2-D06](p2-dash-fleet.md), `rule-edit-preview.html`).

## P2-S14: Dry-run evaluation of an unsaved rule definition

### Scope

- A service that takes a rule definition that is not saved (an edit of an existing rule, or a new rule) and evaluates it against each eligible host's latest config snapshot, using the same evaluator, applicability, and not-readable rules as [P2-S06](p2-cis-engine.md).
- Returns the hosts whose result would change, with the current result, the result under the edited rule, and the observed value. Also returns the counts the preview page shows: hosts that would change (pass to fail, fail to pass, and other), hosts the rule does not apply to, and hosts with no config report.
- Validates the definition with the same checks as an import ([P2-S04](p2-cis-engine.md)) and returns the errors with their JSON Pointers instead of a preview when it is invalid.
- Writes nothing: no results, result changes, rule versions, audit entries, or jobs. It contacts no agent. It reads each host's rules, snapshot, and results without taking a lock that would block an agent report.
- Bounded: a fleet of 50 hosts and a few hundred rules previews in under 2 s; a preview is limited to one rule at a time.
- A preview is advisory. Saving evaluates the rule as it is when saved, so if the rule or a snapshot changed in between, the saved result may differ from what was shown. The preview page says so.

### Acceptance criteria

- [ ] The dry run reports exactly the result changes that saving the same definition produces, on a fleet of mixed results
- [ ] A dry run leaves every table unchanged and enqueues no job (checked by counting rows and jobs)
- [ ] An invalid definition returns its errors with JSON Pointers and no preview
- [ ] A host with no config report, and a host the rule does not apply to, are counted and not listed as changes
