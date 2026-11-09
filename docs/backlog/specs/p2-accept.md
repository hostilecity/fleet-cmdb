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

### As built and measured

- Retention prunes config, package, and inventory snapshots, CIS result changes, report requests, refresh attempts, and findings resolved before the window (`Retention.register … only: { state: "resolved" }`); the newest snapshot of each type per host, current CIS results, and open and reopened findings are kept (`spec/services/retention_spec.rb`).
- `bin/simulate-fleet --load-check` includes Phase 2 (`lib/fleet_simulator/phase2.rb`, [fleet-simulator.md](../../operations/fleet-simulator.md)): the 71 starter CIS rules, 150 simulated advisories, and per host 90 seeded inventory snapshots, 13 seeded config and package reports (800 packages), and both reports at startup.
- **Measured 2026-11-08** (development server, 50 hosts, one simulated hour; 4,500 inventory, 650 config, and 650 package snapshots; 3,550 CIS results; 12,750 open and 8,370 resolved findings): heartbeat p95 76 ms (first quarter 83 ms, last 80 ms); fleet list max 132 ms over 180 loads; compliance view max 98 ms, host vulnerabilities (255 open findings) max 220 ms, package comparison max 105 ms, each over 90 loads; config report p95 116 ms, package report p95 181 ms; every request accepted. No index was needed. Seeding under 16 concurrent requests was slower (package report p95 1.6 s), outside the targets, which cover steady reporting.

## P2-X01: Phase 2 contract tests

### Scope

- Schemas and examples in `docs/api/` for the manifest, config report, package report, and heartbeat directives, with valid and invalid cases.
- Server and agent tests consume them as in [P1-X01](p1-accept.md).
- Backward compatibility with Phase 1 agents and fixtures is not checked: the owner does not require it before the end of Phase 3 (NFR-5, 2026-11-08).

### Acceptance criteria

- [ ] AC-2.6 tests (config validation, rule evaluation, version comparison, matching and resolution) are listed by name for the delivery note

## P2-X02: Phase 2 acceptance run and delivery note

### Scope

- Execute every Phase 2 acceptance criterion on the designated test VM, with evidence.
- The 72-hour agent soak ([P2-SOAK](p2-soak.md)) is not part of this acceptance: the owner moved it to later testing (2026-11-08). The delivery note lists it as not done, with the soak tooling's checked state from [P1-A09](p1-verify.md).
- Confirm the whole suite (Phase 1 included) passes in a clean CI run and the database builds from empty. Migrating a Phase 1 database forward is not checked: the owner rebuilds the test VM from scratch (2026-11-08).
- Update documentation: new agent options, rule import, advisory import and refresh, new operator workflows.
- Confirm nothing out of scope (no remediation) and nothing from Phase 3 was added.
- Delivery note posted on the Phase 2 acceptance issue: what was built, tested, left incomplete, DEC defaults used, and the AC-to-proof table.

### Acceptance criteria

- [ ] All AC-2.x checked off on the Phase 2 acceptance issue with evidence
- [ ] Delivery note posted
- [ ] Owner accepts Phase 2 and closes the milestone
