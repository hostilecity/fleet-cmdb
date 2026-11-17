# P1-AGENT-UPDATE: Agent updater, supervisor, and automatic rollback

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Decided in [ADR 0018](../../decisions/0018-signed-agent-updates.md). Server side: [P1-UPDATES](p1-updates.md). Layout and keys: [P1-PACKAGING](p1-packaging.md).

## P1-A11: Download, verify, and stage

### Scope

- **Acting on the directive.** On an `agent_update` directive for a newer version, the agent downloads the manifest, the signature, and the binary into a staging directory under the state directory. Downloads are resumable and size-capped by the manifest, with a free-space check first.
- **Verification.**
  - The manifest signature is checked against the embedded release public keys.
  - The binary's SHA-256 and size are checked against the manifest, and the manifest's target and version against the directive.
  - The agent refuses any version not newer than the running one. Signed manifests do not expire, so freshness (a held-back or withdrawn release) is a known limit while the rollout server is trusted; see `docs/releases.md`.

  Every refusal is reported as `failed` with the reason, and nothing is installed.
- **Self-test.** The staged binary runs `fleet-agent self-test --config PATH` (empty environment, 30-second limit) before anything changes. It loads the config, builds the HTTPS client with the trusted certificates, and reads the state directory, contacts nothing, and prints `self-test OK: fleet-agent VERSION (agent schema N)`; the agent requires that line with the staged version.
- **One at a time.** One update in progress; a new directive during an update is ignored until it ends. A directive that is answered (refused, or handed to the supervisor) is not acted on again by the same agent process; a download that fails for a transient reason is tried again on the next heartbeats that carry the directive, up to 5 times, and then reported `failed`.
- **No credential, no command.** Downloads carry no credential. Nothing the server sends becomes a path, a command, or a unit name: the version must be canonical SemVer, the URLs only say where to fetch, and the layout is found from where the agent's own binary is.

### Acceptance criteria

- [x] AC-1.9 (agent half): a tampered binary, a bad signature, an unknown key, or an older version is refused and reported, and the running version is unchanged
- [x] An interrupted download resumes, and running out of disk space fails cleanly

## P1-A12: Supervised switch, confirmation, and rollback

### Scope

- **Supervisor.** The running agent starts `systemd-run --unit fleet-agent-update`, running the **current, known-good** binary as `fleet-agent update-supervise --config PATH`. What to do is in the update record the agent wrote (`update.json`), never on the command line. The supervisor holds an exclusive lock (`update.lock`, released when it dies) and is a single decider with write-ahead phases, so it can be killed at any point and started again. The agent's watchdog runs at startup and then every 10 seconds on a timer of its own (never behind the heartbeat loop or its backoff); when it finds an unfinished record and a free lock it relaunches the supervisor from the old binary. It:
  1. verifies the staged files again and installs the staged binary into `versions/<version>/`;
  2. backs up the state records (always: no release declares a state migration yet, and a copy is cheap);
  3. moves `previous` and swaps `current` atomically (rename of a symlink). If the swap reports an error, the supervisor reads `current` back: if it points to the new version (the rename happened and only the directory sync failed), the update goes on as switched and is rolled back if it does not confirm; if it still points to the old version, the update is reported `failed`; if it cannot be read, the record is kept for the next supervisor;
  4. restarts `fleet-agent.service`;
  5. waits for the confirmation marker.

  The service's sandbox ([P1-PACKAGING](p1-packaging.md), `agent/contrib/README.md`) allowed no local sockets, so this issue adds `AF_UNIX` to `RestrictAddressFamilies=` for `systemd-run`; the supervisor's transient unit runs outside that sandbox.
- **Confirmation.** The new version writes the marker (`update-confirmed.json`, naming the rollout, the version, the time the server's acknowledgement arrived, and the kernel boot id) only after its first heartbeat that the server acknowledged. The deadline defaults to 5 minutes and is set by `update_confirm_seconds` in the config (10 to 3600). A marker counts only if it was written by the deadline and in the boot the update started in: a late confirmation is not success, whoever reads it and whenever, and the update is rolled back.
- **Rollback.** Without confirmation by the deadline, the supervisor stops the new version (so nothing it has in flight can overwrite the restored state), swaps back to `previous`, restores the state, starts the service, and records `rolled_back` with the reason. Last, once the rollback is finished and its record removed, it puts `previous` back where it pointed before the switch (the update record keeps that, written before the switch moves it), or removes it when there was none. Not before: the failure hook runs `previous/fleet-agent` as the version being replaced, so `previous` must not move while the hook may still have to finish the rollback. This is done so the version rolled back to keeps its own rollback target and the version before it is not left installed with nothing pointing to it (found by the P1-A09 soak test). If the state cannot be restored, the backup is kept. The restored agent reports it.
- **Backstops.**
  - **Crash loops:** `OnFailure=fleet-agent-rollback.service` in the unit rolls back when the new version keeps failing (`StartLimitBurst`). systemd may start it on every failure; while the supervisor of the update holds the lock it waits (killing that supervisor if it is still holding the lock a minute after its deadline) instead of giving up, and it acts only once it holds the lock itself.
  - **Reboots:** at startup, an agent that finds an unconfirmed update for its own version older than the deadline rolls back. As built, following ADR 0018 and FR-S.5 ("if the VM restarts before it is confirmed"): the record holds the kernel boot id from when the update was staged, and the startup check (the watchdog's first run) starts the supervisor, which rolls back any update past the switch that was not confirmed before the restart, and reports one that had not switched yet as `failed`. An update confirmed before the restart is kept.
  - **Nothing to roll back** (#180, [ADR 0030](../../decisions/0030-agent-recovery-mode.md)): `OnFailure=` names `fleet-agent-recovery.service` after the rollback unit, and the service sets `RestartMode=direct`, so both run once, when the service has given up (its start limit, or exit 78), not after every failed start. The recovery unit waits for the rollback unit (`After=`). As a fallback it checks the service for 20 seconds with `systemctl is-active` and `is-enabled`: it goes on only if it stays `failed` and enabled, exits if it runs (a rollback restarted it) or a person disabled, masked, or reset it (a plain `systemctl stop` of the failed service is not seen; `systemctl stop fleet-agent-recovery` is the way to switch everything off), and fails (systemd retries 5 minutes later) if `systemctl` cannot say. So it goes on when the version that keeps failing is confirmed (or there is no `previous`): `current/fleet-agent run --recovery`, heartbeats with a `recovery` status and the reason, update results, and signed updates only, under the service's sandbox with no capabilities, no netlink, and home hidden. It never confirms an update, and an `updater.lock` keeps it and the service from working on an update at the same time. It exits once the service runs again or a person stops or disables it (checked every 3 seconds). It ends after a fixed release, by an operator, or by recovery mode itself about every hour (no update record, and an offer being downloaded defers it for at most an hour more; never for a service a person disabled, masked, or reset; it starts it without `reset-failed`, so a failed start leaves it `failed` and recovery mode running). No start limit; restarted after 5 minutes to an hour.
  - **Old records:** a record more than 24 hours old is never discarded while the new version may be selected. One that provably never switched (`current` still the old version, checked under the lock) is reported `failed` and cleared; anything else goes to the supervisor, which rolls back an unconfirmed version.
- **Installer.** `fleet-agent install` and `uninstall` take the update lock and refuse, saying an update is in progress, while a supervisor runs or an update record exists, so they cannot remove the version a rollback needs.
- **Retention.** Two versions are kept; older ones are removed after a confirmed update.
- **Result.** The outcome is written to `update-result.json` with a stable `report_id` and posted to `POST /api/v1/update-results` by the running agent after each heartbeat, and retried until accepted (a 4xx other than 429 is dropped and logged, since retrying cannot change it).
- **Units after an update** (#232, lifts this spec's former known limit). Once the update is `Confirmed`, and before it removes the record, the supervisor runs the new, confirmed, signed binary as `versions/<new>/fleet-agent install --refresh-units --quiet`, outside the sandbox (empty environment, 2-minute limit). That subcommand writes this version's three units over the installer's own (and the rollback and recovery units when they are missing), runs `daemon-reload` if any changed, and touches no config, credential, state, or version link; the service is not restarted. It refuses, changing nothing, a unit without the installer's marker (a local copy), a missing `fleet-agent.service`, a `current` that is not the binary running it, and an update in progress that has not confirmed (any record other than a `Confirmed` one for its own version). A refresh that fails is logged and noted in the result's `reason`, and the update stays `succeeded`: the old units run the new binary. Heartbeats carry `units.recovery` (the recovery unit carries the marker and `fleet-agent.service` names it in `OnFailure=`; `false` when unreadable), and the fleet list's "Recovery mode: Not set up" filter lists the hosts without it. **Known limit:** the refresh is the supervisor's, and the supervisor is the version being replaced, so an update *from* a release before #232 does not refresh; the next update, or a re-run of `fleet-agent install`, does.

### As built

- Code: `agent/src/update/` (`stage` and `fetch` for P1-A11, `supervise` for P1-A12, `mod` for the agent side and the commands). State files in the state directory: `update.json`, `update-confirmed.json`, `update-result.json`, `update.lock`, `update/<version>/` (staging) and `update/backup/`.
- Tests: unit tests with a fake clock, fake `systemctl`, and fake release channel; `agent/tests/cli.rs`; and `agent/scripts/update-smoke.sh` (CI job "Update smoke test"), which runs the real units and layout on systemd with throwaway keys and a local stand-in for the API (`update-stub.py`): refused releases, a release that exits at start, a crash-looping one, one that cannot authenticate, the supervisor killed with SIGKILL, a successful update whose result is retried, and an agent below the server's minimum version (NFR-5: the update path uses only `heartbeat`, `update-results`, and the unauthenticated release downloads, none of which return `426`).
- Not covered by CI: a long power-off (more than 24 hours) in the middle of an update, and hardware other than a QEMU/KVM guest. No release verifies in production until the owner generates the release keys (`docs/releases.md`).

### Recorded runs

The workflow **Agent VM tests** (`.github/workflows/agent-vm.yml`, job "Update failure tests on a Debian 13 VM") runs `agent/scripts/vm-test.sh` on every change to `agent/` and on demand. It boots Debian's official Debian 13 genericcloud image (pinned build, SHA-512 checked against Debian's SHA512SUMS and the pinned value) under QEMU with KVM, or TCG with longer timeouts. The VM is configured by a cloud-init NoCloud seed with an SSH key generated in the job. The agent is installed with the real installer against `update-stub.py` on the runner, which the guest reaches at QEMU's host address as `agent.example.lan`; release keys are throwaway. Eight update scenarios (recovery mode runs last, after the package update scenarios):

- the supervisor killed with SIGKILL before the switch, held there by a test-only drop-in on its transient unit (ends `succeeded`);
- the supervisor killed with SIGKILL after the switch (ends `succeeded`);
- `reboot -ff` (a reset with no sync) after the switch and before confirmation (`rolled_back`);
- a reboot after confirmation (the new version is kept);
- a reboot before the switch (`failed`, the old version runs);
- a crash-looping release across a reboot (`rolled_back` by the failure hook);
- a confirmed update from a version running units older than recovery mode (#232): the new version's units are written, systemd is reloaded, the service starts once (for the switch, not for the refresh), and its heartbeats report `units.recovery: true`;
- a crash loop on a confirmed version (#180): a VM fault build (`--cfg fleet_vm_fault`, never in a release) is confirmed, then made to panic at every start; recovery mode starts, heartbeats with the reason and no capabilities, sends no report, installs a fixed release through the signed path, and stops once that release confirms.

Every scenario also checks that recovery mode is not running once it has settled.

Each scenario ends by checking that exactly one working version runs: `current` and `previous`, the installed versions, the service's binary, one agent process, no supervisor and no update record, and a heartbeat the stub acknowledged with the installer's credential. It does so only once the update has settled (no update record or pending outcome, no supervisor or rollback unit running, the service active). It also checks the update result the stub received, and that the configuration (with the credential) is byte-for-byte unchanged. Finally it checks a state record that the test writes before each update and changes while the new version runs: it must hold exactly the new content after a confirmed update and exactly the original after a rollback, so a lost or skipped state backup fails the test. Every scenario is recorded, including one that dies on an unexpected error, and the results are written however the script ends (`vm-test-record.sh`, checked without a VM by `vm-test-record-selftest.sh`). They are uploaded as the `vm-test-results` artifact (JUnit `results.xml`, `results.md`, a log per scenario, and the serial console) and shown in the job summary.

First green run: [Agent VM tests #41567203390](https://github.com/hostilecity/fleet-cmdb/actions/runs/41567203390/job/125691452378) (2026-11-03, KVM, 6 passed in 295 s).

### Acceptance criteria

- [x] AC-1.10: a release that exits at start, one that crash-loops, and one that cannot authenticate are each rolled back automatically, and the rollback is reported
- [x] Killing the supervisor or rebooting the VM mid-update ends with exactly one working version running (failure tests on a disposable VM, results recorded: see Recorded runs)
- [x] A successful update keeps the credential and state, and the next inventory report shows the new version
