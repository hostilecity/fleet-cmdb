# P1-PACKAGING: Signed agent release build and systemd unit

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Signing and the side-by-side layout are decided in [ADR 0018](../../decisions/0018-signed-agent-updates.md); the signature format (minisign) is proposed in [ADR 0021](../../decisions/0021-release-signature-format.md). Formats, key handling, and the release steps are in [docs/releases.md](../../releases.md).

## Scope

- **Release workflow** (`.github/workflows/agent-release.yml`). On a version tag (`agent-v<version>`, on `main`, equal to the `Cargo.toml` version), it builds a static `x86_64-unknown-linux-musl` binary (fleet profile in [DEC-01](../../decisions/0001-fleet-profile.md)) and writes a manifest (version, target, SHA-256, size). It publishes the binary, the manifest, a `SHA256SUMS` file, and the manifest signature as GitHub release assets.
- **Signing.**
  - It happens in a job bound to a protected GitHub environment (`release`) that requires the owner's approval. The Ed25519 private key exists only as that environment's secret.
  - Tag protection and required approvals are documented in this issue's PR.
  - Untagged builds are never signed.
- **Embedded keys.** The release public keys, current and next, are compiled into the agent (`agent/release-keys/`). Key generation and rotation are documented: rotation ships the next key in one release before using it. The agent's verifier (`agent/src/release/`) and `fleet-agent verify-release` check a release exactly as the updater will; Agent CI runs the whole pipeline with a throwaway key on every change.
- **Side-by-side layout,** used by [P1-A10](p1-agent-install.md) and [P1-AGENT-UPDATE](p1-agent-update.md):
  - `/usr/lib/fleet-agent/versions/<version>/fleet-agent`, with `current` and `previous` symlinks;
  - `/usr/bin/fleet-agent` pointing at `current`;
  - config in `/etc/fleet-agent/`, state in `/var/lib/fleet-agent/`.
- **systemd unit, built into the binary** and written by the installer, following [DEC-03](../../decisions/0003-agent-privilege.md): `Restart=on-failure`, `StateDirectory=`, and the hardening options chosen in the ADR. A copy is kept in `agent/contrib/` for review, identical by test. The unit already exists at `agent/src/install/fleet-agent.service`, written to `/etc/systemd/system/` by [P1-A10](p1-agent-install.md) with a baseline of sandboxing options; this issue reviews and finalises it rather than creating it. `OnFailure=` the rollback unit, with its crash-loop limit, and what the updater needs are added by [P1-A12](p1-agent-update.md) (the boundary in [P1-AGENT-INSTALL](p1-agent-install.md)).
- **`agent/contrib/config.example.toml`** with every option documented and placeholder values only.
- **Version.** The agent version embedded in the binary matches the tag.
## Acceptance criteria

- [ ] Binary is statically linked and runs on each distribution in the fleet profile
- [ ] Unit starts on boot, restarts on failure, and logs to the journal
- [ ] A tagged release publishes a manifest signature that verifies against the embedded public key, and an untagged build publishes none
- [ ] `systemd-analyze security` output for the unit is recorded in the PR

## Delivered

- Release workflow with build, sign (environment `release`, owner approval, the only job with the key), and publish (verified with the agent's own `verify-release` and with minisign against `current.pub`) jobs; the repository settings it relies on are listed in [docs/releases.md](../../releases.md).
- Release manifest, minisign signature, and verification in `agent/src/release/`, tested with throwaway keys; `fleet-agent verify-release`.
- `agent/release-keys/current.pub` and `next.pub` hold no key until the owner generates them (docs/releases.md); until then no release verifies and the release workflow refuses to run.
- Unit hardening: `systemd-analyze security` exposure 7.6 to 1.9, recorded with the reason for each option in [`agent/contrib/README.md`](../../../agent/contrib/README.md); checked in CI by `agent/scripts/check-unit.sh`.
- Still to check on a real Debian 13 VM, which CI cannot do: the unit starting on boot under Debian's systemd with this sandbox and the installer seeing the first heartbeat, and the musl binary running on Debian 13 itself (CI runs it on Ubuntu).
