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
- **Rollouts.** `rollouts`, `rollout_hosts` (each chosen host, its stage and state: `pending`, `updating`, `confirmed`, `failed`, `rolled_back`, `unconfirmed`), and `agent_updates` tables. A `rollouts` row has: target release, canary hosts (explicit list or tag), stages (default: canaries, then 25%, then 100%; from `FLEET_ROLLOUT_LARGE_FLEET_HOSTS` active hosts (default 1,000; a whole number from 1 to 100,000,000, anything else, an empty value included, stops the boot) canaries, then 1%, 10%, 50%, and 100%, chosen by `Rollouts.default_stages` for the start form and for `start!` without stages, #199, owner decision on #215), state (`running`, `halted`, `completed`, `cancelled`), and who started, halted, or resumed it. One open (running or halted) rollout at a time, held by a unique index.
  - The target release is a foreign key to `agent_releases` that restricts deletion, so a release a rollout targets is never deleted ([P1-RELEASES](p1-releases.md)).
  - The directive's URLs come from `Releases.download_url`, the same place the install page's do.
  - **Load control (decided here).** Release downloads are limited per client address (60 a minute by default, `FLEET_RELEASE_DOWNLOAD_RATE_LIMIT_PER_MINUTE`), and each update is at least three requests, so many VMs behind one NAT address could hit the limit when a stage opens. Opening a stage gives each of its hosts a fixed offer time: the opening time plus an offset of 0 to `FLEET_ROLLOUT_SPREAD_SECONDS` (default 300) taken from a hash of the rollout and host, and the directive is not sent before it. At the default limit that lets about 100 hosts per address update inside the window; a site with more raises the spread or the limit. A large stage spreads further (#199): its window is the larger of `FLEET_ROLLOUT_SPREAD_SECONDS` and the stage's hosts divided by `FLEET_ROLLOUT_DOWNLOADS_PER_SECOND` (default 10, a whole number from 1 to 100,000; anything else stops the boot), so downloads average at most that rate (75,000 hosts take about 2 hours, not 5 minutes). The offset is `hashtextextended` of the rollout and host ids, modulo the window, computed in SQL when the stage opens. The release downloads stay limited per address, since they are unauthenticated and the installer has no credential (review of #74).
  - A host gets the directive only while its stage is open and it runs an older version.
  - A stage's hosts are chosen before it opens, without the rollout lock, in their own short transactions (#199, review of #215): each statement scans the next 10,000 older hosts after a cursor and inserts them with `ON CONFLICT DO NOTHING` (the unique index skips hosts already chosen), the batch, insert, and cursor in one statement, a batch past the stage's quota trimmed by id. The stage gate (`rollout_hosts.stage <= rollouts.current_stage`) hides them; the advance itself is one short locked update that re-checks the state. So update results and the timeout check never wait for a large stage to be chosen. An operator's advance chooses them in the request; the automatic advance after a stage confirms runs in `RolloutAdvanceJob`, enqueued after the commit that confirmed it, with `RolloutTimeoutJob` enqueuing that job again every minute in case it is lost (it never chooses hosts itself, so the realtime queue is never held up). Prepares of one rollout are serialised by a session-level advisory lock (`pg_try_advisory_lock`, released in `ensure`, as `Liveness.evaluate!` does): a second prepare does nothing (the job and the backstop retry; an operator's Advance is refused with "try again in a minute"), and the stage's quota is counted from the database in every batch, so a stage never opens larger than its percentage (review of #215). Rows chosen for an advance that was refused are re-timed from now when the stage is prepared again. A stage's window is sized from the hosts it will hold, not every older host. A canary tag stays a SQL predicate. The 100% stage takes every older host left, not a count taken before. Hosts chosen for a stage that has not opened are not shown on the Agents page or in the host's "Agent updates" (#245). 100,000 hosts open in about 3 s with no memory growth (it was 39 s and 168 MB). The selection is unchanged: the canaries (active hosts running an older version, by list or tag), then, for each percentage, enough more hosts running an older version, in host id order, to reach that share. A stage advances when all its hosts have confirmed (a failed, rolled back, or unconfirmed host blocks it), or an operator advances it; the last stage completes the rollout.
  - Operator actions are the `Rollouts` service methods `start!`, `advance!`, `halt!`, `resume!`, and `cancel!`, each audited. Their dashboard (P1-D09) is a separate pull request.
- **Outcomes.** `POST /api/v1/update-results` (authenticated) records `succeeded`, `failed` (with reason), or `rolled_back` (with reason) in an `agent_updates` history table.
  - Any `failed` or `rolled_back` halts the rollout and audits it.
  - A host that was sent the directive and does not report within a timeout (`FLEET_UPDATE_CONFIRMATION_TIMEOUT_MINUTES`, default 30; the agent's own rollback deadline is 5 minutes) is marked `unconfirmed` by `RolloutTimeoutJob`, which also halts. A result that arrives late is still stored and confirms the host.
  - A result for a rollout the host is not part of, or for another version than the rollout's release, is `400 validation_failed`. A retried `report_id` is a `200` duplicate.
- **Minimum version.** Agents below the minimum version still receive the directive and may post results (FR-S.5): the `426` check exempts `POST /api/v1/heartbeat` (where the directive is delivered) and `POST /api/v1/update-results`, as it already exempts the release downloads. Every other endpoint, reports included, still answers `426` to an agent below the minimum; the agent does not read directives from a `426`, so none is sent there. An agent below the minimum therefore keeps heartbeating, updates itself, and resumes reporting afterwards ([DEC-18](../../decisions/0018-signed-agent-updates.md)).
- **No rollout row lock per heartbeat (#199, review of #215).** The offer is read without a lock. Only a host's first offer (pending to updating) re-reads the rollout `FOR SHARE SKIP LOCKED`: while a halt, cancel, or advance holds the row there is no directive that heartbeat (the next one tries again), and once a halt or cancel commits no host is offered the update. No heartbeat waits, and a halt waits only for the first offers in flight (about `FLEET_ROLLOUT_DOWNLOADS_PER_SECOND` a second). A host already updating keeps getting its directive until it reports. Before, every heartbeat of a host in an open stage took the row `FOR SHARE`, which at scale meant hundreds of thousands of share lockers of one row.
- **Halts do not use up the spread (#199, review of #215).** `rollouts.halted_seconds` totals the time halted, added on resume; an offer is due at `offer_at + halted_seconds`. So a resume releases what was left of the stage's window, not the whole stage at once, and a stage opened later subtracts the total so earlier halts do not delay it.
- **Intervals.** The directive carries the intervals an operator set (settings `agent.heartbeat_seconds` 10 to 3600 and `agent.inventory_seconds` 60 to 86400; unset means the agent keeps its own). Changing them is an audited setting (`Setting.update_agent_intervals!`). Heartbeats read the intervals through a per-process cache (`SettingsCache`, 10 seconds): the process that saves a change sends it at once, other server processes within 10 seconds (#189). The rollout offer is read in one SELECT with the heartbeat's other directives (`HeartbeatDirectives`), so a heartbeat costs one extra indexed SELECT and no write unless the host is first offered the update.
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
- **As built.**
  - Each action is a confirmation page (GET) and a CSRF-protected POST that calls the `Rollouts` method, as for host actions ([P1-D04](p1-dash-actions.md)). Starting is confirmed too: the form on `/agents` (release, canaries by tag or chosen hosts, later stages such as `25, 100`) opens a page naming the canaries that would be chosen.
  - A confirmation opened for a rollout that has since changed state says so instead of acting, and a POST the state no longer allows changes nothing and shows the service's reason.
  - The Agents page shows the latest rollout, open or finished. Its stage cards count every host; its host table lists the first 200.
  - `rollout_hosts.from_version` keeps the version a host ran when its stage chose it, for the "From" column and the host's "0.1.0 → 0.2.0" history.
  - The host's "Agent updates" lists only rollouts whose stage for the host has opened, the same gate as the Agents page and the offer (`rollout_hosts.stage <= rollouts.current_stage`, #245). A host chosen for a later stage, including by a prepare that was interrupted and never retried, appears once its stage opens; if the stage never opens, it never appears.
  - Every rollout action, and the first offer of the update to a host, refreshes open pages; so does a heartbeat that reports a new agent version.
  - No second factor for these actions in Phase 1: like the other host actions, they need a signed-in operator only.

### Acceptance criteria

- [ ] An operator can run a rollout end to end from the dashboard and see each host's outcome without reloading
- [ ] Halting a rollout requires confirmation, and resuming a halted one shows why it halted
