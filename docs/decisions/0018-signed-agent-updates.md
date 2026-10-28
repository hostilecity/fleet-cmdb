# ADR 0018: Signed remote agent updates with automatic rollback

- Status: Accepted (owner, scope change #54)
- Decision issue: DEC-18
- Requirements: `FR-S.5`, `FR-1.5`, `FR-1.6`, `NFR-1`, `NFR-4`, `NFR-5`, `AC-1.9`, `AC-1.10`
- Amends: [ADR 0003](0003-agent-privilege.md) and [ADR 0014](0014-task-trust-model.md) (consequences only; see below). Lifts the "agent self-update" exclusion in `docs/requirements.md` section 1.

## Context

Upgrading by hand on every VM does not suit a self-sufficient agent, and will not work at the intended end-state scale ([ADR 0019](0019-scale-direction.md)). But the agent runs as root (ADR 0003): whoever chooses the binary an agent installs controls every VM. The server, the dashboard's Google account, and the database must not become that point of control, or the "no arbitrary execution" safeguard of ADR 0003 and ADR 0014 is lost.

## Decision

**Trust.**

- Releases are signed with an Ed25519 key that never touches the server. The release workflow signs on a version tag inside a protected GitHub environment that requires the owner's approval for each release. The key is held only as that environment's secret.
- The agent embeds the release public keys at build time, the current one and the next one, so the key can be rotated.
- Each release has a signed manifest: version, target, SHA-256, and size of the binary. The agent installs nothing whose manifest signature and checksum it has not verified itself.
- The server only says which version to install and where to fetch it. It cannot make an agent run an unsigned binary. It verifies signatures too, but only to refuse bad uploads early; agents do not rely on that check.
- The agent refuses to move to an older version than the one running, so a compromised server cannot push an old, vulnerable signed release. Rollback is local, to the binary that was running before, and never something the server can request.

**Distribution.** The server stores imported releases and serves them to agents on the agent hostname, so a LAN without internet access works. Because artifacts are signed, where they are fetched from does not matter: the manifest URL can later point at a CDN or object store without changing the agent.

**Rollout.** Operators set a target version for the fleet and run a rollout: named canary hosts first, then the rest in stages. The target reaches each agent as a directive in the heartbeat response, as in [ADR 0013](0013-on-demand-reports.md), so agents still make every connection. Any rollback or failed update halts the rollout until an operator resumes it. Every request, success, failure, and rollback is audited.

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

- The main trust anchor becomes the owner's GitHub account and the protected release environment. Protecting them (two-factor authentication, required approval, tag protection) is part of [P1-RELEASES](../backlog/specs/p1-releases.md).
- ADR 0003 still holds (root under a hardened unit). The update path is the single exception to "the server never causes code to run". It is narrow: only binaries signed by the release key, at the same or a newer version.
- ADR 0014 rejected signing tasks. That stands: task safety rests on allowlists, and release signing is a separate mechanism that does not make tasks more powerful.
- New issues: [P1-RELEASES](../backlog/specs/p1-releases.md) (signing and release import), [P1-UPDATES](../backlog/specs/p1-updates.md) (server rollout and dashboard), [P1-AGENT-UPDATE](../backlog/specs/p1-agent-update.md) (updater, supervisor, rollback, failure tests).
- In Phase 3 an agent defers an update while a task is running (P3-AGENT-LEDGER).
