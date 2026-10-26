# P3-SECURITY: Threat model, no-arbitrary-shell review, adversarial and crash tests

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-X01: Phase 3 threat model and security review (including the no-arbitrary-shell check)

### Scope

- Threat model document (drafted early, finalised here) covering the threats in [DEC-14](../../decisions/0014-task-trust-model.md), how each control addresses them, and residual risk. Stored in `docs/decisions/`.
- **No-arbitrary-shell review**, with a written review note (AC-3.2):
  - Enumerate every server route and parameter that reaches task creation, and show none accepts a command, script, path, or executable name.
  - Enumerate every process spawn in the agent and show each uses an absolute path and a fixed vector, no shell, and no parameter in an executable or option position.
  - Search for `sh -c`, string-built commands, `eval`-like constructs, and template-based commands in both codebases.
  - Verify the catalog lint and contract tests are in CI.
- Review every item in FR-3.1 and FR-3.3 against the code and tests; note any gap as an issue before acceptance.
- Dependency audit for both codebases; consider an independent second review given the risk.

### Acceptance criteria

- [ ] Written review note attached to the delivery note
- [ ] Every FR-3.1 and FR-3.3 bullet is mapped to code and a test
- [ ] No open security findings, or each is accepted explicitly by the owner

## P3-X02: Adversarial tests: malformed, malicious, and cross-host task traffic

### Scope

- Direct API tests, not through the dashboard: unknown task type, parameters outside schema (extra fields, wrong types, oversize, injection strings such as `; rm -rf /`, `$(...)`, path traversal, unusual Unicode and control characters), command-like field names, replayed task ids, and tasks for other hosts.
- Agent tests driven by a fake server that sends hostile tasks: the agent refuses them and a canary (a file or process that would only appear if something executed) shows nothing ran.
- Concurrency tests for claiming and for duplicate delivery.
- A fuzz-style test of the parameter validators on both sides.

### Acceptance criteria

- [ ] AC-3.1 proven directly against the API and the agent
- [ ] Every hostile input is refused with the documented error and no execution
- [ ] Tests run in CI

## P3-X03: Crash, restart, and idempotency tests (kill mid-poll and mid-task)

### Scope

- Automated fault-injection tests killing the agent at each step of the task lifecycle: before the `started` record, after it and before the server acknowledgement, mid-execution, after finish and before reporting, and mid-poll.
- Use a task whose side effect is observable (for example appending a line to a test file) to prove it never runs twice.
- Fault-injection hooks exist only in test builds (a cargo feature disabled in release, with a CI check that the release binary does not contain them). Alternatively kill the process externally at timed offsets.
- Server side: simultaneous polls, repeated starts, and duplicate result submissions.
- Restart after kill reports `interrupted` as specified.

### Acceptance criteria

- [ ] No kill point causes a double run in a test matrix of at least 100 randomised runs
- [ ] The release binary contains no fault-injection code (verified in CI)
- [ ] Interruption is reported on the next start
