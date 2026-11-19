# VT-APPLICABILITY: The agent reports the running kernel's build, a pending reboot, and which packages are in use

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed). It feeds rules I1, L1, and N4 and the reboot item of work remaining. It is an agent contract change ([FR-2.3](../../requirements.md#fr-23-package-reporting)); no backward compatibility is needed before Phase 3 ends (NFR-5). The agent keeps its model: it reports facts, the server decides (design principles), and nothing here runs a command chosen by the server.

## What the agent reports today

`kernel_version` (`/proc/sys/kernel/osrelease`, the kernel release such as `6.12.48+deb13-amd64`), `services.running` and `services.enabled` (config facts, from `systemctl`), and every installed package with its source. Enough for rule I1 (which kernel image is running) on the server alone. Not enough for: whether the running kernel is older than the installed image of the same release (Debian updates an image package in place within an ABI), a pending reboot, or which packages a running process uses.

## VT-A01: Without new privileges

### Scope

- Inventory: `kernel_build`, from `/proc/sys/kernel/version` (`uname -v`). On Debian it names the image's package version (for example `#1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 (...)`); the server extracts the version with a per-distribution pattern (the applicability table, VT-S05) and compares it with the installed image's version by dpkg order. No match: the reboot item is not known, never "no reboot needed".
- Inventory: `reboot_required` (true, false, or null when the distribution has no flag): Debian's `/run/reboot-required` exists. The package names in `/run/reboot-required.pkgs`, at most 50, are reported too.
- Package report: `in_use.services`: for each running service unit, the binary package owning its main executable (`systemctl show --property=ExecStart` for the units already listed, then the owning package from dpkg's file lists under `/var/lib/dpkg/info/`, read-only). Bounded: at most 1,000 units, 10 s.
- Everything is read-only, from files and the `systemctl` commands the agent already runs with fixed arguments.

### Acceptance criteria

- [ ] On a test VM after a kernel package update without a reboot, the server shows a pending reboot from `kernel_build`, and after the reboot it does not
- [ ] A running service's package is reported in use; an unparseable `kernel_build` leaves the reboot item "not known"

## VT-A02: Library and socket use (needs the owner's decision, epic question 9)

### Scope

- Package report: `in_use.packages`: each binary package with a file mapped by a running process (`/proc/<pid>/maps`, `/proc/<pid>/exe`) and whether one of those processes owns a listening socket on a non-loopback address (`network`) or only loopback (`loopback`), from `/proc/net/{tcp,tcp6,udp,udp6}` and the socket inodes in `/proc/<pid>/fd`. Also `stale`: a process still maps a deleted version of one of the package's files (it runs old code until restarted). A report with `in_use_complete: true` means a package not listed is idle; otherwise rule L1 never applies.
- Reported: package names and the three classes only. Never process ids, command lines, user names, addresses, or ports.
- Reading other users' processes needs ptrace read access. The agent's unit grants only `CAP_DAC_READ_SEARCH` today, so this needs `CAP_SYS_PTRACE` in the bounding set (epic question 9; the recommended default is off unless the VM's local config enables it, `[packages] in_use = true`, which also keeps the decision on the VM as ADR 0014 does for tasks). Without it the agent reports what it can read (root's own processes) with `in_use_complete: false`.
- Bounded: at most 4,096 processes and 50,000 mapped paths per report, 10 s; mapped paths are matched against dpkg's file lists in one streaming pass. Measure CPU and memory on a 2,000-package host and record them here.
- The threat model gains a row: a compromised agent already has root (ADR 0003); a compromised server learns which packages are used, which it can mostly infer already. Agent-reported classes are untrusted input to triage: a host that lies can only move its own findings.

### Acceptance criteria

- [ ] On a test VM, `smbd` listening on a LAN address marks `samba` `network`, a library used only by a stopped service is idle, and after an upgrade without a restart the library is `stale`
- [ ] The report contains no process id, command line, address, or port, and stays within its time and memory bounds
