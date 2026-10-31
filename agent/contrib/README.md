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
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK` | IPv4 and IPv6 to the server and DNS; netlink for `getifaddrs(3)`. No local (`AF_UNIX`) or packet sockets |
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

[P1-AGENT-UPDATE](../../docs/backlog/specs/p1-agent-update.md) adds `OnFailure=fleet-agent-rollback.service` with a `StartLimitBurst=` crash-loop limit (until then a failing agent is restarted every 10 seconds without limit). Its updater starts the supervisor with `systemd-run`, which talks to systemd over a local socket, so it must add `AF_UNIX` to `RestrictAddressFamilies=`. The supervisor runs as its own transient unit, outside this sandbox, so this unit needs no write access to `/usr/lib/fleet-agent`; if a design gives the running agent that access, add `ReadWritePaths=/usr/lib/fleet-agent` and nothing wider.

### Checking it

`scripts/check-unit.sh` (run in CI) runs `systemd-analyze verify`, failing on any warning, and `systemd-analyze security`, failing above an exposure of 2.0. The exposure went from 7.6 ("EXPOSED") with the baseline unit from P1-AGENT-INSTALL to 1.9 ("OK"). The remaining points are root (0.4), access to the network (0.5 + 0.3 + 0.1), and the other options deliberately left out above. Output on systemd 255:

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
