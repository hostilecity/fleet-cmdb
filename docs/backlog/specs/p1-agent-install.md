# P1-AGENT-INSTALL: One-command agent install, onboarding, and uninstall

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Decided in [ADR 0017](../../decisions/0017-agent-onboarding.md) and [ADR 0018](../../decisions/0018-signed-agent-updates.md). Requirement: FR-S.5 one-command install. Replaces the `enroll` command formerly specified in P1-AGENT-CORE.

## P1-A10: `fleet-agent install` and `fleet-agent uninstall`

### Scope

- **`sudo fleet-agent install --server https://agent.example.lan`**, onboarding by default. In order:
  1. **Preflight.** Running as root, Debian 13 on x86_64 (DEC-01), systemd present, server reachable with a trusted certificate. Each failure prints the cause and the next step.
  2. **Install the binary into the side-by-side layout** (`/usr/lib/fleet-agent/versions/<version>/fleet-agent`, with `current` and `/usr/bin/fleet-agent` links), defined in [P1-PACKAGING](p1-packaging.md). The systemd unit and the default config are built into the binary and written from it.
  3. **Enroll.**
     - **By onboarding:** start onboarding ([P1-ONBOARD](p1-onboard.md)), print the approval URL, the user code, and a QR code of the URL, then poll at the server's interval with a countdown. On approval it writes the config with the credential atomically, mode `0600`. Rejection, expiry, and Ctrl-C each print a clear message and leave no credential behind.
     - **By pre-registered token:** `--token`, or `FLEET_ENROLLMENT_TOKEN`, or `--token-stdin` uses the one-time token instead, so cloud-init and scripts need no person present. The token never appears in the process list, output, or logs.
  4. **Start.** Enable and start the unit, wait for the first acknowledged heartbeat, and print a final summary: host name as approved, version, service status, and where logs are (`journalctl -u fleet-agent`).
- **Idempotent.**
  - Re-running on an enrolled VM keeps the credential and repairs or upgrades the installation; this is also the manual upgrade (NFR-4).
  - `--reenroll` starts onboarding again, for a lost or revoked credential.
  - The `reenrollment_required` log line from [P1-A02](p1-agent-core.md) points to `fleet-agent install --reenroll` or `--token`. The server's message for that error (`cmdb/lib/agent_api.rb`, still naming `fleet-agent enroll --force`) changes in the same PR.
- **`fleet-agent uninstall`** stops and disables the unit, removes the unit, binaries, links, config, and state directory, and prints what it removed. `--keep-state` keeps the config and state for a reinstall. The host record on the server is untouched; retiring it is an operator action.
- **Output** is plain, ordered, and copy-pasteable, with no colour when it is not a terminal. `--quiet` and `--json` exist for scripts.
- **Exit codes** are documented: success, preflight failed, rejected, expired, server error.

### Acceptance criteria

- [ ] AC-1.8 (agent half): on a clean Debian 13 VM, the single documented command plus one approval leaves a running agent whose host appears in the dashboard
- [ ] The token path works with no terminal attached (cloud-init style), and no token, code, or credential appears in output, logs, or the process list
- [ ] A failed install at any step leaves no half-written config, and re-running it succeeds; `uninstall` leaves nothing behind
- [ ] Every preflight failure has a test showing its message and exit code
