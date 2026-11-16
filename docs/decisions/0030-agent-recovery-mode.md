# ADR 0030: Recovery mode for an agent that keeps failing on a confirmed version

- Status: Proposed. The direction is the owner's decision (2026-11-15): "the local supervisor should enter a safe, minimal recovery mode rather than terminating completely so the control plane can still reach and repair it". The design below is for the owner's review
- Decision issue: #180 (agent assessment finding F-A5)
- Requirements: `FR-S.5`, `FR-1.2`, `NFR-1`, `NFR-5`
- Amends: [ADR 0018](0018-signed-agent-updates.md), "Install and rollback on the VM", step 5 (backstops). Every other part of ADR 0018 stands.

## Context

`fleet-agent.service` stops being restarted after four failed starts in five minutes (`StartLimitBurst=4`, `StartLimitIntervalSec=300`), and its `OnFailure=` starts `fleet-agent-rollback.service` (ADR 0018). That unit only acts on an update the new version has not confirmed. When the version that keeps failing is already confirmed, there is nothing to roll back, the unit stays `failed`, and the agent is stopped for good. Only a person on the VM can start it again, and the server cannot help, because agents make every connection.

Causes include a panic in a loop that some server response or host state triggers on every start, and `run` failing to prepare the state directory. On a fresh install the rollback unit cannot even run: there is no `previous` link until the first update.

At the scale the project aims for (ADR 0019), one server response that triggers a bug in a confirmed release would stop every agent that sees it. The owner chose recovery mode over the alternatives in the issue (a delayed restart from the rollback unit, a restart timer, or documenting the manual restart).

## Decision

**Detection is systemd's, and only systemd's.** The start limit stays as it is, so a crash loop still reaches the rollback unit first. `OnFailure=` now names two units, in order: `fleet-agent-rollback.service fleet-agent-recovery.service`. The recovery unit has `After=fleet-agent-rollback.service`, so it waits until the rollback unit has finished.

`fleet-agent.service` sets `RestartMode=direct` (systemd 254 and later; Debian 13 has 257). Without it, systemd 254 and later run `OnFailure=` after *every* failed start, while a restart is still pending: seen in CI, and once noted for the rollback unit in `agent/contrib/README.md`. With it, `OnFailure=` runs once, when the service has given up: its start limit, or an exit status that must not be retried (78). Older systemd ignores the line, and from 239 already runs `OnFailure=` only on the final failure. This also changes when the rollback unit runs (see Consequences).

Recovery mode still checks the service itself, as a fallback, with `systemctl is-active` and `is-enabled`:
- It goes on only for a service that stays `failed` and enabled for 20 seconds, longer than its `RestartSec=10s`.
- It exits, and stays out, if the service runs (`active`, `activating`, `reloading`), for example because a rollback restarted it.
- It also exits and stays out if a person stopped it (`inactive`) or disabled or masked it. A crash loop always ends `failed`, so `inactive` means someone acted, and recovery mode never starts a service a person stopped.
- If `systemctl` cannot say (an error, a timeout, an answer it does not know) for the whole 20 seconds, recovery mode exits with a failure. systemd then starts it again 5 minutes later. It never exits 0 on a guess, which would leave the agent stopped for good.

The unit has no `Conflicts=fleet-agent.service`. On a systemd that runs `OnFailure=` after every failed start, a conflict would cancel the service's own pending restart. Instead recovery mode watches the service every 3 seconds and exits once it runs again, or once a person stops or disables it.

Only one agent process works on an update at a time. The service and recovery mode overlap for at most those 3 seconds, but the updater's guards (`busy`, `last_launch`) are per process. So staging an offer and relaunching a supervisor also take a file lock, `updater.lock` in the state directory, and a process that cannot take it leaves the work to the other: the offer comes again with the next heartbeat, and the watchdog runs again 10 seconds later.

Nothing the server sends can start recovery mode: no directive, no response field, and no file the agent writes on the server's behalf. It is not an agent-side counter either: a counter in the state directory would need its own threshold and window beside systemd's, and could disagree with it.

**What recovery mode does.** `fleet-agent-recovery.service` runs the same binary, `/usr/lib/fleet-agent/current/fleet-agent run --recovery`, which:

1. loads the config and builds the client exactly as `run` does;
2. records the episode in `recovery.json` in the state directory: when it began (kept across restarts until the episode ends) and why. The reason is the agent's own record of why it last stopped with an error (`last-failure.json`, written by `run` on a failing exit, with the first panic's thread, place, and message), with what systemd says about the failure (`$MONITOR_SERVICE_RESULT`, `$MONITOR_EXIT_CODE`, `$MONITOR_EXIT_STATUS`, which `OnFailure=` sets from systemd 251). Plain text, one line, at most 256 characters, no bidirectional controls;
3. sends heartbeats only, each with a `recovery` object (`entered_at`, `reason`, `retry_at`), and posts update results;
4. hands an `agent_update` directive to the same updater as normal mode: the same download, signature and checksum check, no downgrade, self-test, and supervisor (ADR 0018). The watchdog runs as in normal mode, so an update it starts survives a killed supervisor.

It runs no collector and sends no inventory, configuration, or package report. It does not poll for tasks, and its heartbeats carry no `tasks` object, so the server offers it none (P3-A01). Its first acknowledged heartbeat neither confirms an update nor writes the installer's acknowledgement record: only the service in normal mode confirms a version.

**Privileges: the same sandbox, tighter.** The recovery unit has every sandbox option of `fleet-agent.service` and tightens three: `CapabilityBoundingSet=` (none; no collector needs `CAP_DAC_READ_SEARCH`), `ProtectHome=yes`, and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` (no netlink, which only the interface list needs). Its `systemd-analyze security` exposure is 1.6, against the service's unchanged 1.9; `scripts/check-unit.sh` fails CI if it is ever higher than the service's. `AF_UNIX` stays, for `systemd-run` (the update supervisor) and to start the service again.

**Leaving recovery mode.** Recovery mode checks the service every 3 seconds and exits once it runs again (`active` or `activating`), so the two overlap for at most that long. Anything that starts `fleet-agent.service` therefore ends it:

- **a fixed release:** the supervisor restarts the service into the new version, which confirms in normal mode as any update does. If the new version also fails before confirming, the usual rollback returns to the failing version, which fails again, and recovery mode starts again;
- **an operator on the VM:** `systemctl reset-failed fleet-agent` and `systemctl start fleet-agent`. To stop the agent altogether during an episode, stop recovery mode too: `systemctl stop fleet-agent-recovery` (or `systemctl disable fleet-agent`, which recovery mode respects);
- **recovery mode itself, about every hour:** once an hour has passed since it started and no update is in progress, it checks again that the service is still `failed` and enabled, then resets and starts it (`systemctl start --no-block`). It never starts a service a person stopped or disabled. An update record (an update past staging) always defers the try. An offer that is being downloaded defers it for at most another hour, so a server that sends a new offer with every heartbeat cannot keep the agent in recovery mode for good. A cause that has gone away (a server response that is no longer sent, a full disk that was cleared) then ends the episode without anyone acting. A cause that is still there costs four failed starts an hour. If the service cannot be started, recovery mode keeps running and tries again an hour later.

Normal mode removes `recovery.json` and `last-failure.json` once it has run for 10 minutes, longer than the start-limit window, so the episode and its start time survive the hourly tries. The server stores what each heartbeat says: a heartbeat without `recovery` means normal mode.

**If recovery mode itself fails.** The recovery unit has no start limit (`StartLimitIntervalSec=0`) and restarts on any failure after a long delay: `RestartSec=5min`, growing to an hour (`RestartSteps=4`, `RestartMaxDelaySec=1h`; systemd before 254 ignores the two and keeps 5 minutes). It has no `RestartPreventExitStatus=`, so even an invalid config is retried, and the agent comes back by itself once the config is fixed. A panic in recovery mode is recorded as its reason (`recovery mode failed: ...`) for the next start. So the agent is never stopped for good, but a loop that also breaks recovery mode costs one start every hour at most.

**Server.** `heartbeat.request` gains the optional `recovery` object (additive in v1, NFR-5). The heartbeat stores it in its one `UPDATE`: `agent_recovery_since` (the server's time of the episode's first such heartbeat), and the agent's `entered_at`, `retry_at`, and reason for display. A heartbeat without it clears them. A change of mode is broadcast to open pages; a heartbeat in recovery mode is otherwise as cheap as any. The fleet list shows "Recovering" beside the status lamp, and the host page explains it, with the agent's reason (escaped), when it began, and the next step: roll out a release newer than the one it runs, or fix the cause on the VM and start the service. Rollouts treat a host in recovery mode like any other: it gets the directive when its stage is open.

**Rejected:**

- A delayed restart from the rollback unit (`systemd-run --on-active=30min`, the issue's first proposal): the agent stays dark between restarts, so the server cannot see why or send it a fix, and the rollback unit runs `previous`, which a fresh install does not have.
- A `fleet-agent-restart.timer`: the same darkness, and a second schedule to keep in step with the start limit.
- Recovery decided by the agent from its own crash counter: a second, disagreeing definition of a crash loop, and one that must be written before the code that crashes.
- A server directive to enter or leave recovery mode: it would let a server, or anyone who can impersonate it (ADR 0024), switch collectors off fleet-wide. The hourly try of normal mode covers the case a remote "leave" would.
- `Conflicts=fleet-agent.service` on the recovery unit: on systemd 254 and later without `RestartMode=direct`, which start `OnFailure=` units after every failed start, it cancelled the service's own restart after one failure (found by the VM test).
- Deciding only by watching the service, without `RestartMode=direct` (the first version of #222): one look a second can miss a service whose runs last less than that, so recovery mode could start beside pending restarts (review of #222).
- Recovery mode inside `fleet-agent.service` (a flag file read at start): it would share the service's start limit and stop for good in the same way, and could not have its own, tighter sandbox.

## Consequences

- A crash loop on a confirmed version no longer stops the agent for good. The server keeps hearing from it, sees why, and can send a fixed release through the signed update path. The safety of ADR 0018 is unchanged: recovery mode installs only what normal mode would.
- While a host is in recovery mode, its inventory, configuration, and package data, and its compliance and vulnerability results, are as of before; it runs no task. The dashboard says so.
- A crash that recovery mode shares (for example in the heartbeat path) is not cured by it, but costs at most one start every hour and reports nothing; the agent comes back by itself once the cause goes.
- **Rollback timing (owner's OK needed).** With `RestartMode=direct`, the rollback unit runs once, when the service has given up, not after the first failed start. An unconfirmed release that crash-loops is rolled back after its start limit, about 40 seconds (four starts 10 seconds apart), instead of after its first failure. The supervisor still rolls back at its confirmation deadline (5 minutes by default) or as soon as it sees the service `failed`, whichever comes first. Recommendation: accept it. It is what systemd did before 254, it is well inside the confirmation deadline, and a release that fails once and then runs is no longer rolled back for a single transient failure.
- **Release ordering.** The unit files are written only by `fleet-agent install`; an update does not rewrite them (known limit in [P1-AGENT-UPDATE](../backlog/specs/p1-agent-update.md)). So recovery mode needs both a release that has `run --recovery` and the units from that release: fresh installs and re-installs with that release get it; agents updated remotely keep their old units, and today's behaviour, until `fleet-agent install` is run again with the new binary. Issue #232 is the follow-up: a confirmed update refreshes the units, and heartbeats report whether the recovery unit is there, so the dashboard can show which hosts are covered. The server change can deploy first: it only adds optional columns and an optional request field. The new units must not be installed with an older binary: that binary would reject `--recovery` as an unknown argument, which the recovery unit would then retry every hour.
- New threat-model rows: C16, D9, and S8 in [phase-3-threat-model.md](phase-3-threat-model.md).
- Implemented in #180: `agent/src/recovery.rs`, `report::run_recovery`, `agent/src/install/fleet-agent-recovery.service`, the heartbeat schema, `Liveness.recovery_columns`, and the host views. Tested by unit tests, `scripts/check-unit.sh`, and the VM test "Crash loop on a confirmed version: recovery mode" in `agent/scripts/vm-test.sh`, which uses a test-only fault build (`--cfg fleet_vm_fault`, `agent/src/vm_fault.rs`) that `scripts/check-no-fault-hooks.sh` keeps out of releases.
