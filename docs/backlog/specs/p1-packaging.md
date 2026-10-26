# P1-PACKAGING: Agent release build, systemd unit, and install steps

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- Release workflow: on a version tag, build a static `x86_64-unknown-linux-musl` binary (the fleet profile in [DEC-01](../../decisions/0001-fleet-profile.md): Debian 13, x86_64), generate SHA-256 checksums, and publish them as GitHub release assets.
- `contrib/fleet-agent.service` systemd unit following [DEC-03](../../decisions/0003-agent-privilege.md): `Restart=on-failure`, `StateDirectory=`, hardening options chosen in the ADR.
- `contrib/config.example.toml` with every option documented and placeholder values only.
- Install, upgrade, and uninstall steps documented and tested on a clean VM: place the binary, create the service account if needed, enroll, enable the unit; upgrading is replace and restart; uninstall removes the unit, binary, and state.
- Optional convenience installer script, only if it verifies the checksum and requires an explicit version; otherwise documentation only.
- Agent version embedded in the binary matches the tag.

## Acceptance criteria

- [ ] Binary is statically linked and runs on each distribution in the fleet profile
- [ ] Unit starts on boot, restarts on failure, and logs to the journal
- [ ] Documented upgrade preserves the credential and state; uninstall leaves nothing behind
- [ ] `systemd-analyze security` output for the unit is recorded in the PR
