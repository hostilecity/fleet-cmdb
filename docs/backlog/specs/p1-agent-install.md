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
     - **By pre-registered token:** `--token`, or `FLEET_ENROLLMENT_TOKEN`, or `--token-stdin` uses the one-time token instead, so cloud-init and scripts need no person present. The token never appears in the process list, output, or logs: `--token` takes no value and asks for the token on the terminal with the input hidden, and a value given on the command line is refused without being repeated.
  4. **Start.** Enable and start the unit, wait for the first acknowledged heartbeat, and print a final summary: host name as approved, version, service status, and where logs are (`journalctl -u fleet-agent`). The installer itself sends a heartbeat with the config as written, before (re)starting the unit, so a bad credential never replaces a running service; after a (re)start it waits until the unit is active and stays active, and then for the service's own first acknowledged heartbeat: the heartbeat loop of [P1-AGENT-REPORT](p1-agent-report.md) records it in the state directory (`heartbeat.json`, with its process id), and the installer waits for a record naming the unit's main process. The enroll response carries the host's name (`host_name`, additive to v1) so the token path can show it too.
- **Idempotent.**
  - Re-running on an enrolled VM keeps the credential and repairs or upgrades the installation; this is also the manual upgrade (NFR-4).
  - `--reenroll` starts onboarding again, for a lost or revoked credential.
  - The `reenrollment_required` log line from [P1-A02](p1-agent-core.md) points to `fleet-agent install --reenroll` or `--token`, and so does the server's message for that error (`cmdb/lib/agent_api.rb`).
- **`fleet-agent uninstall`** stops and disables the unit, removes the unit, binaries, links, config, and state directory, and prints what it removed. `--keep-state` keeps the config and state for a reinstall. The host record on the server is untouched; retiring it is an operator action.
- **Output** is plain, ordered, and copy-pasteable, with no colour when it is not a terminal. `--quiet` and `--json` exist for scripts.
- **Exit codes** are documented: success, preflight failed, rejected, expired, server error. They are `0` success, `1` a step on the VM failed, `2` usage, `3` preflight failed, `4` rejected, `5` expired or invalid token, `6` server error, `130` interrupted (`agent/README.md`).
- **Boundary with [P1-PACKAGING](p1-packaging.md).** This issue writes the unit built into the binary (`agent/src/install/fleet-agent.service`) to `/etc/systemd/system/fleet-agent.service`, with `Restart=on-failure`, `RestartPreventExitStatus=78`, `StateDirectory=`, and a baseline of sandboxing options. P1-PACKAGING reviews and finalises the hardening (`systemd-analyze security`) and keeps the `contrib/` copy; [P1-AGENT-UPDATE](p1-agent-update.md) adds `OnFailure=` and the write access the updater needs to `/usr/lib/fleet-agent`. The installer copies the running binary into the layout; the signed release build that produces it is P1-PACKAGING.

### Delivered (#57) and what remains

- Delivered: everything above, tested against a local TLS server, a fake root, and a recording systemd (`agent/src/install/tests.rs`), including waiting for the service's own first acknowledged heartbeat once #14 merged.
- Remains: the run on a clean Debian 13 VM (AC-1.8) is recorded under P1-ACCEPT.

### Acceptance criteria

- [ ] AC-1.8 (agent half): on a clean Debian 13 VM, the single documented command plus one approval leaves a running agent whose host appears in the dashboard
- [ ] The token path works with no terminal attached (cloud-init style), and no token, code, or credential appears in output, logs, or the process list
- [ ] A failed install at any step leaves no half-written config, and re-running it succeeds; `uninstall` leaves nothing behind
- [ ] Every preflight failure has a test showing its message and exit code
