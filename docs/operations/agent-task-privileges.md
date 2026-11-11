# Agent task privileges

What each remote task type may do on a VM, how the agent gets that privilege under its hardened systemd unit, and why it is the least that works ([P3-A05](../backlog/specs/p3-agent-exec.md), [DEC-03](../decisions/0003-agent-privilege.md), FR-3.3). The code is `agent/src/tasks/executor/` ([P3-A03](../backlog/specs/p3-agent-exec.md)). A pull request that adds a task type adds its row here and in the threat model's section 6.2.

## The model in one paragraph

The agent runs as root under `fleet-agent.service` (`agent/src/install/fleet-agent.service`): the whole file system read-only except its state directory, one capability (`CAP_DAC_READ_SEARCH`), no new privileges, a system call filter. **That unit is not loosened for tasks.** Each program a task runs declares the privilege it needs (`Program::privilege`), and it runs only for a type whose catalog `privilege` is at least that. A `read_only` or `service_manager` program runs as a child of the agent, inside the same sandbox. A `package_manager` program runs as its own transient systemd unit (`fleet-agent-task-<task id>-<step>.service`) outside the sandbox, started with `systemd-run` over the local socket the unit already allows for the update supervisor, with fixed properties. Every program: absolute path and fixed arguments in the agent's code, at most one validated operand after `--`, no shell, environment exactly `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C`, `DEBIAN_FRONTEND=noninteractive`, working directory `/`, standard input from `/dev/null`, a deadline, bounded output.

## Per-task-type privilege table

| Task type | Catalog `privilege` | Runs as | Privilege used | Why it is the minimum that works |
|---|---|---|---|---|
| `refresh_reports` (P3-A04) | `read_only` | Inside the agent (its collectors) or a child of the agent, in the agent's sandbox | The agent's own: root with `CAP_DAC_READ_SEARCH`, file system read-only except `/var/lib/fleet-agent` | It does what the scheduled reports already do under the same unit (`scripts/sandbox-smoke.sh` proves no fact is lost). Nothing is added |
| `restart_service` (P3-A06) | `service_manager` | `/usr/bin/systemctl restart -- <unit>`, a child of the agent, in the agent's sandbox | Root's right to ask systemd, over `/run/systemd/private` (`AF_UNIX`, already allowed), to restart a unit | Restarting needs the service manager and nothing else: no file write, no capability. systemd itself does the restart outside the sandbox, which is the point. The unit name is the validated operand; the local allowlist and the protected list (DEC-15) decide which (P3-A06) |
| `apply_package_updates` ([P3-AGENT-UPDATES](../backlog/specs/p3-agent-updates.md)) | `package_manager` | `apt-get` in a transient unit `fleet-agent-task-<id>-<n>.service`, outside the agent's sandbox | Root, all capabilities, writes to `/usr`, `/etc`, `/boot`, `/var`, `/root`; minus the agent's credential and state, kernel log, personality and realtime changes, foreign system call ABIs, the shared `/tmp` | dpkg and maintainer scripts write system directories, install setuid programs, change ownership, probe devices, and rebuild initramfs images. None of that is possible inside the agent's unit, and loosening the unit would loosen it for all agent code all the time (threat model F-1). The unit's properties keep what cannot break an upgrade |

`IMPLEMENTED` in `agent/src/tasks/mod.rs` lists `refresh_reports` and `restart_service` ([P3-AGENT-TASKS](../backlog/specs/p3-agent-tasks.md), #36); `apply_package_updates` comes with P3-AGENT-UPDATES. `refresh_reports` runs no program at all: it asks the agent's own report loops for fresh reports. `restart_service` runs only `/usr/bin/systemctl` with `restart`, `is-active`, or `status --no-pager --full --lines=20`, each followed by `--` and the validated unit name. `scripts/task-privilege-smoke.sh` runs the real `restart_service` type under the unit's sandbox against a throwaway, unprotected `cmdb-privsmoke-restart.service`. A type's row becomes true on the test VM when its smoke test passes under the installed unit.

## The agent's unit, reviewed option by option

No option of `fleet-agent.service` had to change for tasks. Each sandbox option was checked against what each privilege needs:

| Option | `read_only` | `service_manager` | `package_manager` |
|---|---|---|---|
| `ProtectSystem=strict` | Fine: writes only the state directory | Fine: `systemctl` writes nothing | Would break it: runs in its own unit instead |
| `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` | Fine | Fine: talking to systemd as uid 0 needs no capability | Would break it (setuid programs, `chown`): own unit |
| `ProtectHome=read-only`, `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateIPC=yes` | Fine | Fine | Would break it (grub probes devices): own unit |
| `ProtectKernel*`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectProc=invisible` | Fine | Fine | Would break it (initramfs, modules): own unit |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` | Fine | Needs `AF_UNIX`, already there for the update supervisor | `systemd-run` needs `AF_UNIX`, already there |
| `SystemCallFilter=@system-service ~@privileged @resources` | Fine | Fine | Own unit |

`systemd-analyze security` (systemd 255, `scripts/check-unit.sh`): **1.9 OK before and after** this change, because the unit did not change. For comparison, the properties of a task unit (`agent/src/tasks/executor/unit.rs`, `PROPERTIES`) score 8.7 "EXPOSED", against 9.4 "UNSAFE" for a plain service running the same program: by design, since a package upgrade needs most of what the score counts.

## The task unit's properties

Fixed in `agent/src/tasks/executor/unit.rs`; no task parameter reaches them.

| Property | Why |
|---|---|
| `Type=exec`, `RemainAfterExit=yes` | `systemd-run` returns once the program started; the unit's result stays readable until the agent collects it (and removes the unit) |
| `KillMode=control-group`, `TimeoutStopSec=60`, `RuntimeMaxSec=<deadline + 60 s>` | Stopping ends every process of the task; `SIGTERM` first, `SIGKILL` 60 seconds later (DEC-16's gentle stop); systemd enforces the deadline even if the agent is gone |
| `WorkingDirectory=/`, `StandardInput=null`, output to the journal, `--setenv` of the three fixed variables | The same execution contract as a direct child. Output goes to the journal so the task keeps running if the agent stops (a pipe to a dead agent would fail maintainer scripts); the agent reads it back by invocation id. systemd adds its own `INVOCATION_ID`, `JOURNAL_STREAM`, and `SYSTEMD_EXEC_PID`, which carry no secret |
| `InaccessiblePaths=-/etc/fleet-agent -/var/lib/fleet-agent` | The task cannot read the agent's credential or tamper with its ledger (threat model C11) |
| `PrivateTmp=yes`, `ProtectKernelLogs=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`, `SystemCallArchitectures=native` | Cannot break a package upgrade, and narrow it a little |
| Not set: `ProtectSystem=`, `ProtectHome=`, `RestrictSUIDSGID=`, `PrivateDevices=`, `NoNewPrivileges=`, `ProtectKernelModules=`, a capability bound | Each breaks something dpkg or a maintainer script does. P3-AGENT-UPDATES reviews the list on the test VM with real upgrades and may narrow it |

The sandbox is not a boundary against code execution inside the agent process: root over the system bus can start any unit (threat model F-2). The guarantee is that agent code never runs anything the server chose (threat model section 8, `scripts/check-task-spawns.sh`). A polkit rule limiting which units the agent may start is left for a later ADR (threat model Q7).

## Agent restarts while a task runs

- `read_only`, interruptible: stopped at once and reported `failed`/`interrupted`.
- A direct child that cannot be interrupted (`restart_service`): up to 45 seconds to finish (below systemd's 90-second stop timeout), then stopped and reported `interrupted`.
- A transient unit that cannot be interrupted (`apply_package_updates`): left running. The ledger keeps the task `started`; the next agent start finds the unit, polls for nothing until it has ended, then reports its exit and output (threat model L8).

## Checking it

- `scripts/check-unit.sh` (CI): the unit's exposure stays at or below 2.0.
- `scripts/task-privilege-smoke.sh` (CI, root, systemd): runs the unit-test binary's `privilege_smoke_*` tests as a service with every `[Service]` option of the real unit: a `read_only` child cannot write `/usr`; `systemctl restart` from inside the sandbox restarts a unit; a `package_manager` program in a task unit can write `/usr`, gets the fixed environment, cannot read `/etc/fleet-agent`, and is stopped at its deadline.
- On the test VM, each task type's pull request (P3-AGENT-TASKS, P3-AGENT-UPDATES) runs it under the installed unit.
