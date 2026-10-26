# P3-ACCEPT: Phase 3 acceptance and delivery note

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- Execute every Phase 3 acceptance criterion on a **disposable** test VM, with evidence.
- Confirm Phase 1 and Phase 2 suites and golden fixtures still pass and migrations run forward cleanly.
- Update documentation: enabling task types on an agent, allowlists, operator workflow, recovery from a half-configured package database, and the privilege model.
- Confirm no remote shell, arbitrary command path, automatic reboot, or out-of-scope feature exists.
- Delivery note on the Phase 3 acceptance issue: built, tested, incomplete, DEC defaults used, the AC-to-proof table, the per-task privilege table, and the AC-3.2 review note ([P3-X01](p3-security.md)).

## Acceptance criteria

- [ ] All AC-3.x checked off on the Phase 3 acceptance issue with evidence
- [ ] Delivery note posted, including the per-task privilege table
- [ ] Owner accepts Phase 3 and closes the milestone
