# P1-UPDATES: Agent rollouts, heartbeat directives, and update history

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Decided in [ADR 0018](../../decisions/0018-signed-agent-updates.md), with the load-control rule from [ADR 0019](../../decisions/0019-scale-direction.md). The agent side is [P1-AGENT-UPDATE](p1-agent-update.md).

## P1-S17: Rollouts and the update directive

### Scope

- **Contract first.** `directives` is an object keyed by directive name ([DEC-20](../../decisions/0020-named-heartbeat-directives.md)); the v1 contract already defines it. Additive v1 changes to `heartbeat.response`:
  - define the fields of `directives.agent_update` (today only "object or `null`"): version, manifest URL, signature URL, binary URL, and rollout id;
  - send `directives.intervals`, already defined (`heartbeat_seconds`, `inventory_seconds`, whole seconds of at least 1), bounded to the agent's allowed range.

  The agent already reads `intervals` and keeps `agent_update` as raw JSON for the updater ([P1-AGENT-REPORT](p1-agent-report.md)). Keep these names, or change the agent in the same pull request.

  Also an `update-result.request` schema for reporting outcomes, and examples for all three.
- **Rollouts.** A `rollouts` table: target release, canary hosts (explicit list or tag), stages (default: canaries, then 25%, then 100%), state (`running`, `halted`, `completed`, `cancelled`), and who started, halted, or resumed it. One running rollout at a time.
  - A host gets the directive only while its stage is open and it runs an older version.
  - A stage advances when all its hosts have confirmed, or an operator advances it.
- **Outcomes.** `POST /api/v1/agent/update-results` (authenticated) records `succeeded`, `failed` (with reason), or `rolled_back` (with reason) in an `agent_updates` history table.
  - Any `failed` or `rolled_back` halts the rollout and audits it.
  - A host that does not report within a timeout is marked `unconfirmed`, which also halts.
- **Minimum version.** Agents below the minimum version still receive the directive and may post results (FR-S.5): the `426` check exempts these paths, and the `426` body for other endpoints includes the directive when one applies.
- **Intervals.** The directive carries the server's configured intervals (settings with bounds). Changing them is an audited setting.
- **Audit.** Every rollout action and every outcome is audited.

### Acceptance criteria

- [ ] AC-1.9 (server half): only hosts in an open stage that run an older version receive the directive, and an agent below the minimum version still receives it
- [ ] AC-1.10 (server half): a reported rollback or a missing confirmation halts the rollout, which resumes only by operator action
- [ ] Every rollout action and outcome is audited, and the contract examples pass through the real endpoints

## P1-D09: Rollout and update history views

### Scope

- **Agent versions page**, following the approved mockups in [P1-D06](p1-dash-actions.md):
  - imported releases;
  - the running rollout with per-stage progress (pending, updating, confirmed, failed, rolled back);
  - start, advance, halt, resume, and cancel, each with confirmation.
- **On host detail**, an "Agent updates" section with the host's update history.
- **Live updates.** The fleet list's agent column and the rollout progress update live over the existing stream ([P1-D05](p1-dash-fleet.md)).

### Acceptance criteria

- [ ] An operator can run a rollout end to end from the dashboard and see each host's outcome without reloading
- [ ] Halting a rollout requires confirmation, and resuming a halted one shows why it halted
