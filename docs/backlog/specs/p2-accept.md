# P2-ACCEPT: Phase 2 retention, performance, contract tests, acceptance

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-S12: Retention and performance for Phase 2 data

### Scope

- Register config snapshots, package snapshots, rule result changes, and resolved findings with the retention job from [P1-S10](p1-operability.md); defaults per [DEC-07](../../decisions/0007-snapshots-and-retention.md); always keep the latest snapshot per host and type.
- Extend the [P1-O04](p1-verify.md) simulator to send config and package reports (realistic sizes) and re-run the 50-host load check.
- Query review: fleet compliance view, host vulnerabilities, and package diff within the performance targets; add indexes as measured, not guessed.
- Confirm heartbeat latency is unaffected by the new tables.

### Acceptance criteria

- [ ] Pruning removes expired Phase 2 snapshots and keeps the newest per host
- [ ] Fleet compliance view and fleet list each load in under 2 seconds with 50 hosts (numbers recorded)
- [ ] Heartbeat p95 remains under 200 ms

## P2-X01: Phase 2 contract tests and backward compatibility

### Scope

- Schemas and examples in `docs/api/` for the manifest, config report, package report, and heartbeat directives, with valid and invalid cases.
- Server and agent tests consume them as in [P1-X01](p1-accept.md).
- The frozen Phase 1 golden fixtures still pass unchanged against the Phase 2 server. If a Phase 1 schema needed a change, the version is bumped with a documented migration.
- An agent from the end of Phase 1 (previous release) is run against the Phase 2 server in CI or by a documented manual check: it must keep working, and ignore the new directives.

### Acceptance criteria

- [ ] Phase 1 fixtures pass unchanged
- [ ] Previous agent release works against the new server
- [ ] AC-2.6 tests (config validation, rule evaluation, version comparison, matching and resolution) are listed by name for the delivery note

## P2-X02: Phase 2 acceptance run and delivery note

### Scope

- Execute every Phase 2 acceptance criterion on the designated test VM, with evidence.
- Confirm migrations run forward from the Phase 1 database and the whole suite (Phase 1 included) passes in a clean CI run.
- Update documentation: new agent options, rule import, advisory import and refresh, new operator workflows.
- Confirm nothing out of scope (no remediation) and nothing from Phase 3 was added.
- Delivery note posted on the Phase 2 acceptance issue: what was built, tested, left incomplete, DEC defaults used, and the AC-to-proof table.

### Acceptance criteria

- [ ] All AC-2.x checked off on the Phase 2 acceptance issue with evidence
- [ ] Delivery note posted
- [ ] Owner accepts Phase 2 and closes the milestone
