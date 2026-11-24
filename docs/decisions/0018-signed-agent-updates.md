# ADR 0018: Signed remote agent updates with automatic rollback

- Status: Accepted (owner, scope change #54); amended by [ADR 0030](0030-agent-recovery-mode.md): a crash loop with nothing to roll back to ends in recovery mode, not a stopped agent; and by #251 (owner, 2026-11-23): a host whose agent keeps restarting after the update counts as failed for its stage ("Restart loops" below)
- Decision issue: DEC-18
- Requirements: `FR-S.5`, `FR-1.5`, `FR-1.6`, `NFR-1`, `NFR-4`, `NFR-5`, `AC-1.9`, `AC-1.10`
- Amends: [ADR 0003](0003-agent-privilege.md) and [ADR 0014](0014-task-trust-model.md) (consequences only; see below). Lifts the "agent self-update" exclusion in `docs/requirements.md` section 1.

## Context

Upgrading by hand on every VM does not suit a self-sufficient agent, and will not work at the intended end-state scale ([ADR 0019](0019-scale-direction.md)). But the agent runs as root (ADR 0003): whoever chooses the binary an agent installs controls every VM. The server, the dashboard's Google account, and the database must not become that point of control, or the "no arbitrary execution" safeguard of ADR 0003 and ADR 0014 is lost.

## Decision

**Trust.**

- Releases are signed with an Ed25519 key that never touches the server. The release workflow, started by the owner on `main` with the version to release, signs inside a protected GitHub environment that requires the owner's approval for each release, and only then creates the version tag. The version is compiled into the binary by the release run, so a release needs no commit (owner, 2026-11-08: the owner cannot build the agent locally). The key is held only as that environment's secret.
- The agent embeds the release public keys at build time, the current one and the next one, so the key can be rotated.
- Each release has a signed manifest: version, target, SHA-256, and size of the binary. The agent installs nothing whose manifest signature and checksum it has not verified itself.
- The server only says which version to install and where to fetch it. It cannot make an agent run an unsigned binary. It verifies signatures too, but only to refuse bad uploads early; agents do not rely on that check.
- The agent refuses to move to an older version than the one running, so a compromised server cannot push an old, vulnerable signed release. Rollback is local, to the binary that was running before, and never something the server can request.

**Distribution.** The server stores imported releases and serves them to agents on the agent hostname, so a LAN without internet access works. Because artifacts are signed, where they are fetched from does not matter: the manifest URL can later point at a CDN or object store without changing the agent.

**Rollout.** Operators set a target version for the fleet and run a rollout: named canary hosts first, then the rest in stages. The target reaches each agent as a directive in the heartbeat response, as in [ADR 0013](0013-on-demand-reports.md), so agents still make every connection. Any rollback or failed update halts the rollout until an operator resumes it. Every request, success, failure, and rollback is audited.

**Restart loops (#251, owner decision 2026-11-23).** A release that leaks memory slowly is killed at the unit's `MemoryMax=` and restarted by systemd 10 seconds later. If the kills come minutes apart it never reaches the start limit, so nothing rolls it back, and each new process authenticates, heartbeats, and confirms normally. So each canary looks healthy, and the rollout would go on to the whole fleet. To see it:

- Heartbeats carry an optional `process` object (additive in v1): the process's start, systemd's `NRestarts` for `fleet-agent.service` (read once per process with `systemctl show`), and how the process before it stopped. The stop comes from the unit's `ExecStopPost=` (`fleet-agent note-stop`), which records the `$SERVICE_RESULT`, `$EXIT_CODE`, and `$EXIT_STATUS` systemd gives it. The running agent cannot read the stop with `systemctl show` itself: systemd resets `Result`, `ExecMainCode`, and `ExecMainStatus` when it starts the service again, auto-restarts included. `note-stop` runs in the service's own sandbox, as root, and writes only one state record. The unit's `systemd-analyze security` exposure stays 1.9.
- The server counts restarts from `NRestarts`: a rise counts the difference, and a fall (a manual start, an update, or a boot reset it) counts the new value. It keeps the server's time of the last 32 restarts on the host, and writes the hosts row only when something changed.
- **A host of the open rollout that restarts more than `FLEET_RESTART_LOOP_RESTARTS` times (default 3, 1 to 31) within `FLEET_RESTART_LOOP_WINDOW_HOURS` (default 24, 1 to 168) counts as failed.** The rule:
  - Only a host the rollout offered the update counts, while it is `updating` or `confirmed`, and while the rollout is open: from the offer to the end of the rollout, across later stages.
  - Only restarts strictly after the offer count, and only those within the window.
  - **Baseline (owner decision 2026-11-23):** a host with more than the limit within the window *before* its offer was already looping, for example a host with too many packages for its memory limit. It does not count towards the halt. Its first offer stores that count (`rollout_hosts.restarts_before_offer`), and the rollout and host pages show it as "looping before this update".
  - A counted host is marked `restart_loop` and audited (`update.restart_loop`), at most once per rollout. Its stage cannot complete, and a running rollout halts until an operator resumes it, as for a rollback. A late `succeeded` result is stored and keeps the mark: the host runs the release and keeps restarting.
  - The halt reason names the host, the count, the window, and the last stop in words, for example "killed at its memory limit".
  - The check runs only on a heartbeat that shows a new restart, so a steady heartbeat pays nothing for it.
- **Stage observation time (owner decision 2026-11-23).** Once every host of a stage has confirmed, the stage stays open for `FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES` (default 30, 0 for none, at most 10,080) before the next stage opens. Restarts keep counting meanwhile, so a release whose leak needs 20 minutes or more for its fourth restart halts at the canaries, before any other host is chosen.
  - The last stage is observed too, before the rollout completes: once completed, nothing can halt it.
  - The rollout page shows "All confirmed; observing until HH:MM UTC".
  - A stage without hosts is not observed.
  - A resume observes the stage again from the resume.
  - An operator's Advance opens the next stage at once: it is an operator's choice.
  - `RolloutTimeoutJob` moves the rollout on, within a minute of the end of the observation.
  - A loop slower than the observation time (4 restarts in more than 30 minutes) can still pass a stage; raise the setting for slower ones.
- The same restart-loop settings drive the fleet list's "Restarted: more than N times in H hours" filter and the host page's notice. The filter reads only the hosts that loop: the (limit + 1)th newest restart is stored in an indexed column. After lowering `FLEET_RESTART_LOOP_RESTARTS`, `bin/rails restart_loops:refresh` stores it again.

**Install and rollback on the VM.**

1. Versions live side by side (`/usr/lib/fleet-agent/versions/<version>/`), with `current` and `previous` links.
2. The agent downloads to a staging directory, checks free space, verifies the signature and checksum, and runs the new binary's self-test (version and config check).
3. The running, known-good binary then starts a transient supervisor unit (`systemd-run`). The supervisor swaps `current` atomically and restarts the service.
4. The update counts as good only when the new version has authenticated and completed a heartbeat the server acknowledged, within a deadline (default 5 minutes). Otherwise the supervisor swaps back and restarts the previous version.
5. Two backstops cover what the supervisor cannot:
   - **Crash loops:** a unit `OnFailure=` hook rolls back.
   - **Reboots:** at startup, an agent that finds an unconfirmed update after a reboot rolls it back.
6. Local state stays readable by the previous version, or is backed up before the swap.
7. The outcome is reported on the next heartbeat.

**Old agents.** The minimum-version check (`426`) must never cut an agent off from updates. The update directive and the release download are served to agents below the minimum.

**Fallback.** Re-running `fleet-agent install` with a newer binary is the documented manual upgrade (NFR-4).

**Rejected:**

- Server-side signing: a server compromise would mean fleet-wide root.
- Unsigned updates over TLS: TLS authenticates the server, not the release.
- In-place binary replacement: no safe rollback.
- Letting the new binary judge its own health: a broken binary cannot be trusted to roll itself back.
- The owner signing on a personal machine: stronger, but slower; possible later by moving the key, without changing agents.

## Consequences

- The main trust anchor becomes the owner's GitHub account and the protected release environment. Protecting them (two-factor authentication, required approval, protection of `main` and of published tags) is part of [P1-RELEASES](../backlog/specs/p1-releases.md).
- ADR 0003 still holds (root under a hardened unit). The update path is the single exception to "the server never causes code to run". It is narrow: only binaries signed by the release key, at the same or a newer version.
- ADR 0014 rejected signing tasks. That stands: task safety rests on allowlists, and release signing is a separate mechanism that does not make tasks more powerful.
- New issues: [P1-RELEASES](../backlog/specs/p1-releases.md) (signing and release import), [P1-UPDATES](../backlog/specs/p1-updates.md) (server rollout and dashboard), [P1-AGENT-UPDATE](../backlog/specs/p1-agent-update.md) (updater, supervisor, rollback, failure tests).
- In Phase 3 an agent defers an update while a task is running (P3-AGENT-LEDGER).
- **First installs (owner, 2026-11-15, #181).** "Installs nothing it has not verified itself" covers updates; a first install is run by a person before any agent exists. The install commands now check the release signature too, with the public key from the repository on GitHub (`agent/release-keys/current.pub` at the release's tag), not a checksum the server shows. The server stays out of the trust path for first installs as for updates; GitHub (the repository and its tags) is the trust anchor, as it already is for releases. Details and what remains trusted: [install-agent.md](../operations/install-agent.md#install-one-vm-approved-in-the-dashboard), threat model C16.
