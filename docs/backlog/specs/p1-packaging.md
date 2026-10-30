# P1-PACKAGING: Signed agent release build and systemd unit

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Signing and the side-by-side layout are decided in [ADR 0018](../../decisions/0018-signed-agent-updates.md).

## Scope

- **Release workflow.** On a version tag, it builds a static `x86_64-unknown-linux-musl` binary (fleet profile in [DEC-01](../../decisions/0001-fleet-profile.md)) and writes a manifest (version, target, SHA-256, size). It publishes the binary, the manifest, a `SHA256SUMS` file, and the manifest signature as GitHub release assets.
- **Signing.**
  - It happens in a job bound to a protected GitHub environment (`release`) that requires the owner's approval. The Ed25519 private key exists only as that environment's secret.
  - Tag protection and required approvals are documented in this issue's PR.
  - Untagged builds are never signed.
- **Embedded keys.** The release public keys, current and next, are compiled into the agent. Key generation and rotation are documented: rotation ships the next key in one release before using it.
- **Side-by-side layout,** used by [P1-A10](p1-agent-install.md) and [P1-AGENT-UPDATE](p1-agent-update.md):
  - `/usr/lib/fleet-agent/versions/<version>/fleet-agent`, with `current` and `previous` symlinks;
  - `/usr/bin/fleet-agent` pointing at `current`;
  - config in `/etc/fleet-agent/`, state in `/var/lib/fleet-agent/`.
- **systemd unit, built into the binary** and written by the installer, following [DEC-03](../../decisions/0003-agent-privilege.md): `Restart=on-failure`, `StateDirectory=`, the hardening options chosen in the ADR, and `OnFailure=` the rollback unit ([P1-A12](p1-agent-update.md)). A copy is kept in `contrib/` for review. The unit already exists at `agent/src/install/fleet-agent.service`, written to `/etc/systemd/system/` by [P1-A10](p1-agent-install.md) with a baseline of sandboxing options; this issue reviews and finalises it rather than creating it.
- **`contrib/config.example.toml`** with every option documented and placeholder values only.
- **Version.** The agent version embedded in the binary matches the tag.
## Acceptance criteria

- [ ] Binary is statically linked and runs on each distribution in the fleet profile
- [ ] Unit starts on boot, restarts on failure, and logs to the journal
- [ ] A tagged release publishes a manifest signature that verifies against the embedded public key, and an untagged build publishes none
- [ ] `systemd-analyze security` output for the unit is recorded in the PR
