# agent/contrib

Reference copies for review ([P1-PACKAGING](../../docs/backlog/specs/p1-packaging.md)). Nothing here is installed from this directory: `fleet-agent install` writes the unit and the config from what is built into the binary.

| File | What it is |
|---|---|
| `fleet-agent.service` | The systemd unit, byte for byte as the installer writes it to `/etc/systemd/system/`. The source is `../src/install/fleet-agent.service`; a test fails if the two differ (after editing the source: `cp src/install/fleet-agent.service contrib/` in `agent/`) |
| `config.example.toml` | Every config option, documented, with placeholder values. A test fails if an option the agent accepts is missing from it, or if its values are not the defaults |

## The unit's sandbox

The agent runs as root ([DEC-03](../../docs/decisions/0003-agent-privilege.md)) under the sandbox below. What it must keep doing: read `/etc/fleet-agent`, the trust store in `/etc/ssl`, `/proc`, `/sys`, and the mount table; call `statvfs` on every mount; make outbound HTTPS connections, with DNS; and write its state directory. `fleet-agent install` waits for the service's own first accepted heartbeat, recorded in the state directory, so a sandbox that breaks any of this fails the install. `the_sandbox_keeps_what_the_agent_needs` in `src/install/systemd.rs` pins the options that would break it silently.

| Option | Why |
|---|---|
| `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` | Root keeps one capability: reading and searching files and directories it does not own, so `statvfs` reaches a mount below another user's directory. Everything the agent writes is root's own. Drops `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and the rest |
| `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` | No way back to more privileges through setuid programs |
| `ProtectSystem=strict` | The whole file system is read-only for the agent except `StateDirectory=` (`/var/lib/fleet-agent`). A `state_dir` elsewhere needs `ReadWritePaths=` in a drop-in; the agent says so at startup |
| `ProtectHome=read-only` | Not `yes`/`tmpfs`: those replace `/home` with an empty mount, and a separate `/home` disk would then be reported with the wrong size |
| `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateIPC=yes` | The agent uses no shared `/tmp`, no device, and no System V IPC. It never opens `/dev/<disk>`: mount sources are only compared as text |
| `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes` | `/proc/sys` and `/sys` stay readable, as the collectors need, but not writable; no modules, kernel log, cgroup changes, or clock changes |
| `ProtectProc=invisible` | Other users' processes are hidden; the agent reads only `/proc/self/*` and system-wide files |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` | IPv4 and IPv6 to the server and DNS; netlink for `getifaddrs(3)`; a local socket for `systemd-run`, which starts the update supervisor (P1-AGENT-UPDATE). No packet sockets |
| `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes` | Nothing the agent uses |
| `SystemCallFilter=@system-service`, `~@privileged @resources`, `SystemCallErrorNumber=EPERM` | The agent's system calls, traced while it heartbeats and reports, are all in `@system-service` and none in the denied groups. A call outside the filter fails with `EPERM`, which the collectors report as a warning, instead of killing the agent |
| `SystemCallArchitectures=native`, `UMask=0077` | Native x86_64 calls only; files private by default |

Deliberately not set:

| Option | Why not |
|---|---|
| `User=`, `DynamicUser=`, `PrivateUsers=` | DEC-03: root, so later phases can read root-only data. Phase 3 reviews hardening per task |
| `ProtectHostname=yes` | Gives the service its own copy of the host name at start, so a later rename would never be reported |
| `ProcSubset=pid` | Hides `/proc/cpuinfo`, `/proc/meminfo`, `/proc/net/route`, which the collectors read |
| `PrivateNetwork=`, `IPAddressDeny=` | The agent must reach the server, whose address the unit does not know |

### What P1-AGENT-UPDATE adds

[P1-AGENT-UPDATE](../../docs/backlog/specs/p1-agent-update.md) adds, to `fleet-agent.service`:

- `StartLimitIntervalSec=300`, `StartLimitBurst=4` and `OnFailure=fleet-agent-rollback.service`. Before it, a failing agent was restarted every 10 seconds without limit. systemd starts the rollback unit when the service has given up. `RestartMode=direct` (systemd 254 and later; earlier versions behave so already) makes that once, when four starts in five minutes end the restarts or the exit status is 78; without it, systemd 254 and later start it after every failed start (seen on Ubuntu 24.04 in CI). So an unconfirmed release that crash-loops is rolled back after about 40 seconds, unless the supervisor's confirmation deadline comes first (#180, ADR 0030). The rollback unit returns to the previous version only if an agent update has not been confirmed, and does nothing at any other time. If the supervisor of that update still holds the update lock, the rollback unit waits for it rather than giving up (otherwise a supervisor that died after the last failure would leave nobody to roll back), and kills it if it is still holding the lock a minute past its own deadline; it acts only once it holds the lock itself. Hence `TimeoutStartSec=4000`.
- `AF_UNIX` in `RestrictAddressFamilies=`. The updater starts the supervisor with `systemd-run`, which talks to systemd over a local socket. This is the only option the update needed; the exposure score is checked by `scripts/check-unit.sh` as before.

The supervisor runs as its own transient unit (`fleet-agent-update`), outside this sandbox, so the service needs no write access to `/usr/lib/fleet-agent`; if a design gives the running agent that access, add `ReadWritePaths=/usr/lib/fleet-agent` and nothing wider.

`fleet-agent-rollback.service` (`Type=oneshot`) runs `/usr/lib/fleet-agent/previous/fleet-agent update-rollback --reason crash-loop`: the previous version's binary, the one that was known to work. It has no `ProtectSystem=` because it has to change `/usr/lib/fleet-agent` and the state directory and restart the service, but it keeps the other restrictions that do not get in its way. `fleet-agent install` writes the three units; `uninstall` stops recovery mode and removes them. A confirmed update rewrites the installer's own units from the new version (`install --refresh-units`, #232); a unit without the installer's marker is left alone.

### How the agent stopped (#251)

`ExecStopPost=-/usr/lib/fleet-agent/current/fleet-agent note-stop`: after every stop of the service, systemd runs the same binary with `$SERVICE_RESULT`, `$EXIT_CODE`, and `$EXIT_STATUS` set. `note-stop` writes them to `last-stop.json` in the state directory, and the next process reports them in its heartbeats (`process.last_stop`), with systemd's `NRestarts`. The running agent cannot read them with `systemctl show`, because systemd resets `Result`, `ExecMainCode`, and `ExecMainStatus` when it starts the service again, auto-restarts included. It runs under this unit's sandbox and writes only that record: no privilege is added, and the exposure stays 1.9. The `-` prefix means it never fails the stop. It runs after a kill at `MemoryMax=` too, once the killed processes have freed their memory. The recovery unit has no `ExecStopPost=`: its own stops are not the service's. A VM gets the line when its units are written: by the installer, or by the unit refresh after a confirmed update (#232). Until then its heartbeats send `last_stop: null`, and still send the restart count, which needs no unit change.

### Recovery mode (#180)

`OnFailure=fleet-agent-rollback.service fleet-agent-recovery.service`: after the rollback unit, [`fleet-agent-recovery.service`](fleet-agent-recovery.service) runs `current/fleet-agent run --recovery` when there was nothing to roll back ([ADR 0030](../../docs/decisions/0030-agent-recovery-mode.md)). Its options:

- `After=fleet-agent-rollback.service`: it starts only once the rollback unit has finished.
- No `Conflicts=fleet-agent.service`: on a systemd that runs `OnFailure=` after every failed start (254 and later without `RestartMode=direct`), a conflict would cancel the service's own restart after one failure. Instead the agent checks the service itself, as a fallback, for 20 seconds (`is-active`, `is-enabled`): it goes on only if it stays `failed` and enabled, exits if it runs or a person made it `inactive` (`reset-failed`) or disabled or masked it, and fails, so systemd retries in 5 minutes, if `systemctl` cannot say. Once running, it checks every 3 seconds and exits when the service runs again or a person does one of those. A plain `systemctl stop fleet-agent` is not seen (a `failed` unit stays `failed`): to stop the agent altogether during an episode, use `systemctl stop fleet-agent-recovery`, or disable, mask, or reset the service.
- `StartLimitIntervalSec=0`, `Restart=on-failure`, `RestartSec=5min`, `RestartSteps=4`, `RestartMaxDelaySec=1h`: never stopped for good; a failing recovery mode is retried after 5 minutes, growing to an hour (systemd 254 and later; earlier versions keep 5 minutes). No `RestartPreventExitStatus=`, so it comes back by itself once a broken config is fixed. No `[Install]`: nothing starts it at boot.
- The sandbox is this unit's, with three options tighter: `CapabilityBoundingSet=` (none: recovery mode runs no collector, so it needs no `CAP_DAC_READ_SEARCH`; root still reads and writes its own root-owned files, and systemd authorizes its `systemd-run` and `systemctl` calls by user id), `ProtectHome=yes`, and no `AF_NETLINK` (only the interface list needs it). `systemd-analyze security`: 1.6. `scripts/check-unit.sh` fails CI if it is ever above the service's.

### Memory and task limits (#182)

`fleet-agent.service` and `fleet-agent-recovery.service` set:

| Option | Why |
|---|---|
| `MemoryMax=128M` | The ceiling. The kernel first reclaims the cgroup's page cache; a charge it still cannot fit ends in an OOM kill inside the agent's own cgroup, never against the VM's workload |
| `MemorySwapMax=0` | Without it, a leak on a VM with swap would be pushed to swap instead of reaching `MemoryMax`, and slow the whole VM. With it, `MemoryMax` is the real ceiling |
| `OOMPolicy=stop` | The default (`DefaultOOMPolicy=`), set here so a host's `system.conf` cannot change it: when the kernel kills any process of the unit, systemd stops the rest and restarts it as for any failure. Not `continue`: an agent whose `dpkg-query` child was killed would carry on under the same pressure. `scripts/sandbox-smoke.sh` tests this case |
| `TasksMax=64` | Processes and threads of the unit. A thread leak or a runaway `fork` gets `EAGAIN` instead of using up the VM's PIDs |

No `MemoryHigh=` (owner, 2026-11-18). With no swap, almost all of the agent's memory is anonymous, so above `MemoryHigh` the kernel would have almost nothing to reclaim and could only slow the agent down: a leaking agent would be slow and stale for minutes, with no restart, and its `dpkg-query` could hit its 20-second limit and send a misleading "unreadable" package report. With `MemoryMax` alone, a leak ends in a kill and a restart.

**One listing at a time.** The package report and `apply_package_updates` both run `dpkg-query`. The agent runs one at a time (`ONE_LISTING_AT_A_TIME` in `src/packages.rs`, tested by `listings_run_one_at_a_time`), so the limit has to fit one listing, not two.

**What it rests on.** The owner's 72-hour soak (#99): about 7.5 MiB resident (8.2 MiB at most), 8 threads, 9 descriptors, flat. The limits count the whole cgroup: the agent, its direct children (`dpkg-query`, `systemctl`, the self-test of a staged update), and the page cache it brings in. Measured with a release build in its own memory and pids cgroups (2026-11-19, listings serialised):

| Path | Memory peak (cgroup) | Tasks peak |
|---|---|---|
| Start, reports, heartbeats on a host with 1,047 packages | 9.4 MiB | 24 |
| A 20,000-package report (the most a report may list; `scripts/dpkg-status-large.py`) | 75 MiB, of which `dpkg-query` 71 MiB | 19 |
| `refresh_reports` on that host (inventory, config, packages) | 81 MiB | 22 |
| The 20,000-package report with a cold page cache (the agent the first to read the 24 MB status file, as after a boot) | 99 MiB, of which about 24 MiB reclaimable page cache | 26 |
| The same under a real 128M limit | 98 MiB; no OOM kill, every package sent | 24 |
| Inventory with 1,000 extra mounts (first round, 2026-11-18) | 76 MiB | 18 |
| Update download, signature and checksum check, and self-test (first round) | 16 MiB (5 MiB of it the staged binary in the page cache) | 24 |

A warm cache is the usual case: the CI runner writes its synthetic database, so those pages are charged to the runner, not the agent. A real status file also holds stanzas of removed packages, which `dpkg-query` parses too. **Where 128M is reached:** `dpkg-query` needs about 3.6 KiB per installed package, so it, not the agent, sets the margin. Under a real 128M limit, a host with 34,000 packages peaked at 123 MiB and kept running; one with 36,000 had its `dpkg-query` killed. So about **35,000 installed packages**, 1.75 times the 20,000 a report may list. Typical Debian hosts have hundreds to a few thousand. A host past the 20,000 cap sends no list, but still runs the listing. Past about 35,000 packages each listing would be killed, and the agent restarted (`OOMPolicy=stop`). It does not normally reach recovery mode. After a restart, the startup package report waits a random 0 to 10 minutes (the restart splay, #200), so the kills come about 5 minutes apart on average. That rarely fits enough kills into the start limit's 5 minutes: in the review's simulation, about 1% of such hosts within an hour and 25% within a day. Meanwhile the agent heartbeats at every start, so the host looks online, but it never sends a package report, and `NRestarts` keeps growing. Since #251 the heartbeats report those restarts and the kill, and the fleet list's "Restarted" filter shows the host. Raise `MemoryMax` with a drop-in there (below). `restart_service` adds one `systemctl` child (a few MiB, four tasks). `apply_package_updates` runs apt in task units of its own; the agent side is the listings and the journal reads (about 8 MiB on Debian 13 in the VM test). `scripts/sandbox-smoke.sh` repeats the 20,000-package measurement on the CI runner under the real unit, and `scripts/vm-test.sh` records the peaks of the package update scenarios on Debian 13; both fail if a limit is reached.

**Not counted.** The update supervisor (`fleet-agent-update`), package upgrades (`fleet-agent-task-*`), and the rollback unit run in units of their own, with no limit: none of them is a child of the agent's cgroup. `fleet-agent-rollback.service` has no limit on purpose: it acts after the service failed, perhaps because of a limit, and must never be the step a limit stops (`memory_and_task_limits_bound_the_agent_but_never_the_rollback` in `src/install/systemd.rs`).

**When a limit is reached:**

- **`MemoryMax`:** the kernel reclaims page cache, then its OOM killer kills the largest process of the cgroup (the agent, or its `dpkg-query`), and systemd stops the rest of the unit (`OOMPolicy=stop`). The kernel logs `Memory cgroup out of memory: Killed process ...` with `oom_memcg=/system.slice/fleet-agent.service`; that line is the reliable sign. systemd's own result can read either `Failed with result 'oom-kill'` or, when the agent itself was the victim and systemd sees its exit before the cgroup's OOM event, `Failed with result 'signal'` with status `KILL` (both seen in CI). It is a `SIGKILL`: the agent writes nothing on the way out, which its state already survives, because every record is written to a temporary file and renamed, and the task ledger is appended and flushed with `fsync` before a step returns (the P3-X03 kill points cover a kill at any point).
- **`TasksMax`:** a new thread or process fails with `EAGAIN`. Where the agent starts the thread or process itself, it reports the error and keeps running: a collector warning, a failed task step, or a failed update with "cannot read its output". But the HTTP client (ureq 3.5, with a global timeout set) resolves each new connection's host name on a thread it starts with `thread::spawn`, which panics when it cannot start. The loop that made the request then fails, and the agent exits and is restarted. A resolver thread whose lookup timed out also lives on until `getaddrinfo` returns, so very slow DNS adds threads. The measured peaks used a local stand-in server, with no slow DNS.
- **Then `Restart=on-failure`** restarts it 10 seconds later. A one-off spike costs one restart. A task that was running is reported `interrupted` (`refresh_reports`, `restart_service`); an `apply_package_updates` upgrade runs on in its own unit and is collected after the restart (threat model L8).
- **The start limit.** Killed at four starts within five minutes, the service stops being restarted and fails, and `OnFailure=` starts the rollback unit and then recovery mode, exactly as for a crash loop (ADR 0030). Recovery mode has the same limits but runs no collector, so a leak in a collector does not follow it; if it is killed too, it is restarted after 5 minutes, growing to an hour, and never gives up. Its reason ends with systemd's result: `fleet-agent.service kept failing and systemd stopped restarting it (oom-kill, last exit killed KILL)`, or `(signal, last exit killed KILL)` when systemd saw the exit first. A leak that takes longer than about a minute to reach the limit never makes four kills within five minutes: the agent is restarted each time and stays in normal mode, and the server does not see the restarts yet (#251).
- **During an update.** The download, check, and self-test run in the agent's cgroup. A kill there leaves only staged files, which the next offer resumes. Nothing is installed before the supervisor runs. If the agent is killed after writing the update record but before the supervisor started, its watchdog starts the supervisor at the next start, as after any crash. After the switch, a new version that is killed before it confirms is a release that fails before it confirms: the supervisor, outside the cgroup, rolls it back at its deadline or as soon as it sees the service failed, and the rollback unit does it if the supervisor is gone. A realistic leaking release sends its first heartbeat within seconds and confirms before it gets near the limit, so it is not rolled back: it is restarted, or ends in recovery mode, as above. CI's leaking release (`scripts/update-smoke.sh`, group `limits`) never sends a heartbeat. It shows that the kernel kills it at `MemoryMax` in the service's cgroup and that the update is still rolled back cleanly, not that the limit causes the rollback. The restart of a confirmed agent and the path to recovery mode are shown by the group's two drop-in scenarios.

**Raising a limit.** With a drop-in (`systemctl edit fleet-agent`; see [troubleshooting.md](../../docs/operations/troubleshooting.md#the-agent-was-killed-for-using-too-much-memory)), never by editing the unit, which the installer and the unit refresh replace. `MemoryMax=infinity` removes one.

**Other systems.** `MemorySwapMax=` exists only on the unified cgroup hierarchy (v2). A host on cgroup v1 or the hybrid layout (#163), or one booted with `swapaccount=0`, ignores it, so there a leak can go to swap first. `MemoryMax=` and `TasksMax=` work on both.

**Units from earlier installers.** The lines are in the units that `fleet-agent install` writes, and that a confirmed update now writes too (`install --refresh-units`, #232). The refresh runs `daemon-reload`, which puts the limits in force on the running service at once (checked in `scripts/update-smoke.sh`, scenario "success"). That is after the update has confirmed, so a limit too tight for a host is not rolled back with the release; raise it with a drop-in. The refresh is run by the supervisor of the version being replaced, so an update from a release without #232 does not refresh the units. The next update does, and so does re-running the installer. Until then `systemctl show fleet-agent -p MemoryMax` prints `infinity`.

**Checked by:**
- `src/install/systemd.rs`: the values, the recovery unit's, and none in the rollback unit.
- `src/packages/tests.rs`: one listing at a time, with a mutation-checked test.
- `scripts/sandbox-smoke.sh`:
  - the limits are in force on the running unit, checked through `systemctl show` and the cgroup's own files;
  - the 20,000-package host stays below them;
  - with `MemoryMax=48M`, the kernel kills `dpkg-query`, not the agent, and `OOMPolicy=stop` stops the whole unit.
- `scripts/update-smoke.sh`, group `limits`:
  - the limits are in force on the installed units;
  - a leaking unconfirmed release is OOM-killed and rolled back;
  - a confirmed agent killed by a lowered `MemoryMax` drop-in is restarted, with its heartbeat, state and unchanged ledger;
  - one killed at every start reaches recovery mode, then is normal again once the drop-in is gone.
- `scripts/vm-test.sh` scenario 374: the limits are applied on Debian 13, never reached, and the peaks are recorded.

The new error path in `stage::run_bounded` (a reader thread that cannot start) has no test: it needs a thread start to fail on demand.

### What Phase 3 tasks add

Nothing to this unit ([P3-A05](../../docs/backlog/specs/p3-agent-exec.md)). `read_only` and `service_manager` task programs run as children of the agent inside this sandbox (`systemctl restart` reaches systemd over the `AF_UNIX` socket already allowed); `package_manager` programs run in a transient unit, `fleet-agent-task-<id>-<step>.service`, outside it, with fixed properties. The per-task privilege table and the option-by-option review are in [`docs/operations/agent-task-privileges.md`](../../docs/operations/agent-task-privileges.md). `scripts/task-privilege-smoke.sh` (CI) proves each privilege works under this unit's options.

### Checking it

`scripts/sandbox-smoke.sh` (run in CI on the runner's systemd) runs the musl release binary as a transient service with every `[Service]` option of this unit, read from the file so the test cannot drift, against a local stand-in for the agent API, and once without them. The sandboxed run must have its heartbeat accepted, write its state (including its task ledger, P3-A02), and report every fact the unsandboxed run reports, with no new warning; a system call the filter blocks (`SystemCallErrorNumber=EPERM`) would otherwise only show as a missing fact.

`scripts/check-unit.sh` (run in CI) runs `systemd-analyze verify` on the service together with the rollback unit, failing on any warning, and `systemd-analyze security`, failing above an exposure of 2.0. The exposure went from 7.6 ("EXPOSED") with the baseline unit from P1-AGENT-INSTALL to 1.9 ("OK"). The remaining points are root (0.4), access to the network (0.5 + 0.3 + 0.1), and the other options deliberately left out above. Output on systemd 255:

```text
  NAME                                                        DESCRIPTION                                                                    EXPOSURE
✗ RootDirectory=/RootImage=                                   Service runs within the host's root directory                                       0.1
✗ User=/DynamicUser=                                          Service runs as root user                                                           0.4
✗ CapabilityBoundingSet=~CAP_(DAC_*|FOWNER|IPC_OWNER)         Service may override UNIX file/IPC permission checks                                0.2
✗ ProtectHostname=                                            Service may change system host/domainname                                           0.1
✗ RestrictAddressFamilies=~AF_NETLINK                         Service may allocate netlink sockets                                                0.1
✗ RestrictAddressFamilies=~AF_(INET|INET6)                    Service may allocate Internet sockets                                               0.3
✗ ProtectHome=                                                Service has read-only access to home directories                                    0.1
✗ ProcSubset=                                                 Service has full access to non-process /proc files (/proc subset=)                  0.1
✗ PrivateNetwork=                                             Service has access to the host's network                                            0.5
✗ PrivateUsers=                                               Service has access to other users                                                   0.2
✗ DeviceAllow=                                                Service has a device ACL with some special devices: char-rtc:r                      0.1
✗ IPAddressDeny=                                              Service does not define an IP address allow list                                    0.2

→ Overall exposure level for fleet-agent.service: 1.9 OK :-)
```

(Only the failing rows are shown; every other check passes. `ProtectHostname=` is reported although the service cannot change the host name without `CAP_SYS_ADMIN`. `DeviceAllow=char-rtc:r` comes from `ProtectClock=`.)
