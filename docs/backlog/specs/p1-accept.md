# P1-ACCEPT: Phase 1 acceptance and delivery note

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-X01: Phase 1 API contract tests and frozen payload fixtures

### Scope

- Request specs on the server that send every valid example in `docs/api/examples/` to the real endpoints and assert the documented response, and every invalid example and assert the documented error.
- Agent tests that serialise real report structs and validate them against the same schemas.
- Freeze the Phase 1 payloads as `v1` golden fixtures. Later phases must keep accepting them (or increase `schema_version` with a documented migration).
- Test that an older agent version is still accepted, and that one below the minimum receives the documented error.
- Test the update path as part of the contract (NFR-5): an agent version below the minimum, and the previous release, can still heartbeat, receive the `agent_update` directive, download the release files, and post `update-results`, while their reports get `426`. This test is kept in every later phase.
- Enrollment, heartbeat, inventory validation, liveness transitions, and credential revocation each have a named test mapped to AC-1.7 for the delivery note.

### Acceptance criteria

- [ ] Changing a schema without updating the examples fails CI
- [ ] Golden fixtures are never edited by later phases without a version bump (CI check or review rule documented)
- [ ] A table linking AC-1.7 subjects to test names is ready for the delivery note
- [ ] The update path stays open to an agent below the minimum version (heartbeat, directive, downloads, results), and the test is named in the delivery note

## P1-X02: Phase 1 acceptance run and delivery note

### Scope

Run every Phase 1 acceptance criterion on the designated test VM ([DEC-01](../../decisions/0001-fleet-profile.md)) and write the delivery note.

- AC-1.1 to AC-1.10 each executed, with evidence (test name, command output, or screenshot). AC-1.8 is run by someone following only the dashboard install page; AC-1.9 and AC-1.10 use a disposable VM and test releases signed with the real release process.
- NFR-2: restore drill result. NFR-3: load check numbers from [P1-O04](p1-verify.md). FR-1.6: the soak runs from [P1-A09](p1-verify.md) (the 72-hour run is [P2-SOAK](p2-soak.md), in Phase 2).
- Migrations run forward cleanly from an empty database and the full suite passes in a clean CI run.
- Documentation reviewed against what was built.
- Confirm nothing out of scope and nothing from Phase 2 or 3 was added.
- Delivery note posted on the Phase 1 acceptance issue: what was built, what was tested, anything incomplete, every DEC recommended default that was used, and the table mapping each acceptance criterion to its proof.

### Acceptance criteria

- [ ] All AC-1.x checked off on the Phase 1 acceptance issue with evidence links
- [ ] Delivery note posted
- [ ] Owner accepts Phase 1 and closes the milestone
