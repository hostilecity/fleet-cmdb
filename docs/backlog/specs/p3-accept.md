# P3-ACCEPT: Phase 3 acceptance and delivery note

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- Execute every Phase 3 acceptance criterion on a **disposable** test VM, with evidence.
- Confirm Phase 1 and Phase 2 suites still pass and the database builds from empty. Earlier golden fixtures and agents are not checked (NFR-5: backward compatibility starts after Phase 3).
- Update documentation: enabling task types on an agent, allowlists, operator workflow, recovery from a half-configured package database, and the privilege model.
- Confirm no remote shell, arbitrary command path, automatic reboot, or out-of-scope feature exists.
- Delivery note on the Phase 3 acceptance issue: built, tested, incomplete, DEC defaults used, the AC-to-proof table, the per-task privilege table, and the AC-3.2 review note ([P3-X01](p3-security.md)).

## Acceptance criteria

- [ ] All AC-3.x checked off on the Phase 3 acceptance issue with evidence
- [ ] Delivery note posted, including the per-task privilege table
- [ ] Owner accepts Phase 3 and closes the milestone

## Prepared (#39)

- **Runbook:** [`docs/operations/phase-3-acceptance.md`](../../operations/phase-3-acceptance.md): for each AC-3.x, what CI already proves (job, scenario, test names), the steps on a disposable Debian 13 VM, what counts as a pass, and what evidence to save; the CI runs for the earlier suites and the empty database; the no-shell, no-reboot, and out-of-scope checks.
- **Documentation:** enabling task types, allowlists, the step-up, creating and cancelling, and every result and reason in [`fleet-operations.md`](../../operations/fleet-operations.md#remote-tasks); recovery from a half-configured package database in [`troubleshooting.md`](../../operations/troubleshooting.md#the-package-database-needs-repair); the privilege model, checked against the code with file references, in [`agent-task-privileges.md`](../../operations/agent-task-privileges.md).
- **Delivery note:** drafted in the pull request's description, as Phases 1 and 2 posted theirs on the acceptance issue; the owner fills the evidence and posts it on #39.
- **Not checked, by scope:** earlier agent releases and frozen fixtures (NFR-5). The database is built from empty by loading the schema in CI; running every migration from empty gives the same structure (checked by hand on `78047da`).
