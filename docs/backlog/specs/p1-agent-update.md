# P1-AGENT-UPDATE: Agent updater, supervisor, and automatic rollback

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Decided in [ADR 0018](../../decisions/0018-signed-agent-updates.md). Server side: [P1-UPDATES](p1-updates.md). Layout and keys: [P1-PACKAGING](p1-packaging.md).

## P1-A11: Download, verify, and stage

### Scope

- **Acting on the directive.** On an `agent_update` directive for a newer version, the agent downloads the manifest, the signature, and the binary into a staging directory under the state directory. Downloads are resumable and size-capped by the manifest, with a free-space check first.
- **Verification.**
  - The manifest signature is checked against the embedded release public keys.
  - The binary's SHA-256 and size are checked against the manifest, and the manifest's target and version against the directive.
  - The agent refuses any version not newer than the running one.

  Every refusal is reported as `failed` with the reason, and nothing is installed.
- **Self-test.** The staged binary runs its self-test (`fleet-agent self-test`: version, config parse, state readable) before anything changes.
- **One at a time.** One update in progress; a new directive during an update is ignored until it ends.

### Acceptance criteria

- [ ] AC-1.9 (agent half): a tampered binary, a bad signature, an unknown key, or an older version is refused and reported, and the running version is unchanged
- [ ] An interrupted download resumes, and running out of disk space fails cleanly

## P1-A12: Supervised switch, confirmation, and rollback

### Scope

- **Supervisor.** The running agent starts `systemd-run --unit fleet-agent-update`, running the **current, known-good** binary as `fleet-agent update-supervise <version>`. The supervisor:
  1. installs the staged binary into `versions/<version>/`;
  2. backs up the state if the new version declares a state migration;
  3. moves `previous` and swaps `current` atomically (rename of a symlink);
  4. restarts `fleet-agent.service`;
  5. waits for the confirmation marker.
- **Confirmation.** The new version writes the marker only after its first heartbeat that the server acknowledged. The deadline defaults to 5 minutes.
- **Rollback.** Without confirmation by the deadline, the supervisor swaps back to `previous`, restores state if backed up, restarts, and records `rolled_back` with the reason. The restored agent reports it.
- **Backstops.**
  - **Crash loops:** `OnFailure=fleet-agent-rollback.service` in the unit rolls back when the new version keeps failing (`StartLimitBurst`).
  - **Reboots:** at startup, an agent that finds an unconfirmed update for its own version older than the deadline rolls back.
- **Retention.** Two versions are kept; older ones are removed after a confirmed update.
- **Result.** The outcome is posted to `POST /api/v1/agent/update-results` and retried until accepted.

### Acceptance criteria

- [ ] AC-1.10: a release that exits at start, one that crash-loops, and one that cannot authenticate are each rolled back automatically, and the rollback is reported
- [ ] Killing the supervisor or rebooting the VM mid-update ends with exactly one working version running (failure tests on a disposable VM, results recorded)
- [ ] A successful update keeps the credential and state, and the next inventory report shows the new version
