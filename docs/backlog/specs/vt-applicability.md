# VT-APPLICABILITY: The agent reports listening services, the reboot flag, and (where enabled) library use

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (approved by the owner, 2026-11-19), not in the first cut (epic decision 21), and blocked by VT-HOST-TAB because it adds the in-use signals to the tab (the agent half can be written earlier). It feeds rule N5 (owner decision 2026-11-21: in-use evidence only escalates; [VT-EPIC](vt-epic.md) decision 27) and the reboot work item. This slice writes the adapter `VulnerabilityTriage::HostFacts.listener_source` (#277 leaves it off). It is an agent contract change ([FR-2.3](../../requirements.md#fr-23-package-reporting)); no backward compatibility is needed before Phase 3 ends (NFR-5). The agent reports facts and the server decides; nothing here runs a command chosen by the server.

## What the server already knows without this slice

The package report lists every installed kernel image and the inventory has the running kernel release (`kernel_version`), so rules I1, K1, and K2 and "reboot into the installed kernel" need no agent change (VT-S05). In trixie each kernel update is a new package, so "a newer image is installed and not running" is exactly a pending kernel reboot. This slice adds what the server cannot infer.

## VT-A01: Listening services and the reboot flag, with no new privilege

### Scope

- **Listening sockets**: read `/proc/net/{tcp,tcp6,udp,udp6}` (no privilege): local address, port, state, uid, and socket inode for each listening TCP socket and bound UDP socket.
- **Socket to service**: ask the kernel's `sock_diag` netlink interface for the same sockets with their cgroup id (`INET_DIAG_CGROUP_ID`, what `ss --cgroup` shows); map the cgroup id to its cgroup path under `/sys/fs/cgroup` (the directory's inode number is the id), the path to the systemd unit, the unit to its main executable (`systemctl show --property=ExecStart`, which the agent already runs with fixed arguments), and the executable to its binary package (dpkg's file lists under `/var/lib/dpkg/info/`, read-only). The unit already allows `AF_NETLINK` (`agent/src/install/fleet-agent.service`), so nothing in it changes; the exposure stays 1.9 (`agent/scripts/check-unit.sh` fails above 2.0).
- **Report**, in the package report: `in_use.listening`, each binary package owning a listening service with its class, `network` (any non-loopback address) or `loopback`, and `in_use.services`, the packages of running services' executables. Never process ids, command lines, user names, addresses, or ports. A socket whose cgroup is not a systemd service (a container, a user session) is counted, not named.
- **Reboot flag** in the inventory: `reboot_required` is true when Debian's `/run/reboot-required` exists, with `/run/reboot-required.pkgs` (at most 50 names); **null, never false, when it does not**, because Debian's kernel packages have not reliably created it (Debian bug #1010699, as the review notes). The server's own kernel rule (a newer image installed and not running) is the main signal; the flag adds reboots for other packages (for example libc).
- **Kernel build** (`/proc/sys/kernel/version`, which on Debian names the image's package version) is reported for distributions that update a kernel package in place (#163); Debian 13 does not need it.
- Bounded: at most 10,000 sockets and 1,000 units, 10 s. Measure on a 2,000-package host and record CPU and memory here.

### Acceptance criteria

- [ ] On a test VM, `smbd` listening on a LAN address marks `samba` `network`, and `sshd` bound to 127.0.0.1 only marks `openssh-server` `loopback`, with no change to the agent's unit and its exposure still 1.9
- [ ] A missing `/run/reboot-required` is reported as null, and the report has no process id, command line, address, or port

## VT-A02: Library use and stale code (optional, off by default)

### Scope

- Which packages' files are mapped by running processes (`/proc/<pid>/maps`, `/proc/<pid>/exe`), and `stale` (a process still maps a deleted version of a package's file, so it runs old code until restarted). Only this needs ptrace read access to other processes.
- **Never in the main unit.** `CAP_SYS_PTRACE` is not read-only: it allows `PTRACE_MODE_ATTACH` and reading `/proc/<pid>/mem` of every process, so in the network-facing agent a file-read bug would disclose other processes' secrets (threat model F-2: the sandbox exists for non-exec bugs). Adding it to `fleet-agent.service` raises its `systemd-analyze security` exposure from 1.9 to 2.2, above the 2.0 gate (measured in the review). And the agent cannot work around it: `ProtectProc=invisible` and the capability rules hide every other user's process and every root daemon with more capabilities than the agent's.
- **A separate, short-lived unit**, as `apply_package_updates` runs apt (threat model F-1): the agent starts a transient oneshot (`systemd-run`, fixed unit name and properties) running its own binary in a scan mode with `CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`, `PrivateNetwork=yes`, `ProtectSystem=strict`, no write access except one result file in the state directory, `RuntimeMaxSec=30`. The main agent reads the file. The scan receives no input from the server.
- **Off by default.** Enabled only on the VM, `[packages] library_scan = true` in the local config (as task types are enabled locally, ADR 0014). With it off nothing carries the capability. A report says whether the scan ran (`in_use_complete`); no rule demotes a finding on in-use evidence (decision 27).
- Reported: package names and classes only. Bounded: at most 4,096 processes and 50,000 mapped paths, 30 s.
- A threat model row is added when built: the capability lives only in a no-network oneshot with a fixed program and no server input, for at most 30 s every package report.

### Acceptance criteria

- [ ] With the scan off, no unit on the VM carries `CAP_SYS_PTRACE`; with it on, only the transient scan unit does, and it has no network
- [ ] With the scan on, a library used only by a stopped service is idle, and after an upgrade without a restart the library is `stale`
