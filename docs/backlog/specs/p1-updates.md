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
- **Rollouts.** `rollouts`, `rollout_hosts` (each chosen host, its stage and state: `pending`, `updating`, `confirmed`, `failed`, `rolled_back`, `unconfirmed`), and `agent_updates` tables. A `rollouts` row has: target release, canary hosts (explicit list or tag), stages (default: canaries, then 25%, then 100%), state (`running`, `halted`, `completed`, `cancelled`), and who started, halted, or resumed it. One open (running or halted) rollout at a time, held by a unique index.
  - The target release is a foreign key to `agent_releases` that restricts deletion, so a release a rollout targets is never deleted ([P1-RELEASES](p1-releases.md)).
  - The directive's URLs come from `Releases.download_url`, the same place the install page's do.
  - **Load control (decided here).** Release downloads are limited per client address (60 a minute by default, `FLEET_RELEASE_DOWNLOAD_RATE_LIMIT_PER_MINUTE`), and each update is at least three requests, so many VMs behind one NAT address could hit the limit when a stage opens. Opening a stage gives each of its hosts a fixed offer time: the opening time plus an offset of 0 to `FLEET_ROLLOUT_SPREAD_SECONDS` (default 300) taken from a hash of the rollout and host, and the directive is not sent before it. At the default limit that lets about 100 hosts per address update inside the window; a site with more raises the spread or the limit. The release downloads stay limited per address, since they are unauthenticated and the installer has no credential (review of #74).
  - A host gets the directive only while its stage is open and it runs an older version.
  - A stage's hosts are chosen when it opens: the canaries (active hosts running an older version, by list or tag), then, for each percentage, enough more hosts running an older version, in host id order, to reach that share. A stage advances when all its hosts have confirmed (a failed, rolled back, or unconfirmed host blocks it), or an operator advances it; the last stage completes the rollout.
  - Operator actions are the `Rollouts` service methods `start!`, `advance!`, `halt!`, `resume!`, and `cancel!`, each audited. Their dashboard (P1-D09) is a separate pull request.
- **Outcomes.** `POST /api/v1/update-results` (authenticated) records `succeeded`, `failed` (with reason), or `rolled_back` (with reason) in an `agent_updates` history table.
  - Any `failed` or `rolled_back` halts the rollout and audits it.
  - A host that was sent the directive and does not report within a timeout (`FLEET_UPDATE_CONFIRMATION_TIMEOUT_MINUTES`, default 30; the agent's own rollback deadline is 5 minutes) is marked `unconfirmed` by `RolloutTimeoutJob`, which also halts. A result that arrives late is still stored and confirms the host.
  - A result for a rollout the host is not part of, or for another version than the rollout's release, is `400 validation_failed`. A retried `report_id` is a `200` duplicate.
- **Minimum version.** Agents below the minimum version still receive the directive and may post results (FR-S.5): the `426` check exempts `POST /api/v1/heartbeat` (where the directive is delivered) and `POST /api/v1/update-results`, as it already exempts the release downloads. Every other endpoint, reports included, still answers `426` to an agent below the minimum; the agent does not read directives from a `426`, so none is sent there. An agent below the minimum therefore keeps heartbeating, updates itself, and resumes reporting afterwards ([DEC-18](../../decisions/0018-signed-agent-updates.md)).
- **Intervals.** The directive carries the intervals an operator set (settings `agent.heartbeat_seconds` 10 to 3600 and `agent.inventory_seconds` 60 to 86400; unset means the agent keeps its own). Changing them is an audited setting (`Setting.update_agent_intervals!`). A heartbeat costs two extra indexed SELECTs and no write unless the host is first offered the update.
- **Audit.** Every rollout action and every outcome is audited, and so is the first offer of the update to each host (`update.requested`), so a host asked to update is on its audit trail even if the rollout is cancelled before it reports.

### Acceptance criteria

- [ ] AC-1.9 (server half): only hosts in an open stage that run an older version receive the directive, and an agent below the minimum version still receives it on a `200` heartbeat while its reports still get `426`
- [ ] AC-1.10 (server half): a reported rollback or a missing confirmation halts the rollout, which resumes only by operator action
- [ ] Every rollout action and outcome is audited, and the contract examples pass through the real endpoints

## P1-D09: Rollout and update history views

### Scope

- **Agent versions page**, following the approved mockups in [P1-D06](p1-dash-actions.md):
  - imported releases (already on `/agents` from P1-RELEASES, with the imports);
  - the running rollout with per-stage progress (pending, updating, confirmed, failed, rolled back);
  - start, advance, halt, resume, and cancel, each with confirmation.
- **On host detail**, an "Agent updates" section with the host's update history.
- **Live updates.** The fleet list's agent column and the rollout progress update live over the existing stream ([P1-D05](p1-dash-fleet.md)).

### Acceptance criteria

- [ ] An operator can run a rollout end to end from the dashboard and see each host's outcome without reloading
- [ ] Halting a rollout requires confirmation, and resuming a halted one shows why it halted
