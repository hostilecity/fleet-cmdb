# P1-AGENT-COLLECT: Agent system, disk, and network collectors

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-A04: Collector framework and system facts

### Scope

- A collector abstraction in which each field is collected independently and returns either a value or a typed error. A failure produces `null` plus a collection warning (field and reason), never an aborted report.
- Collectors: hostname, operating system name and version (`/etc/os-release`: id, version id, pretty name), kernel version, architecture, CPU model and core count, total and available memory, uptime, boot identifier (`/proc/sys/kernel/random/boot_id`), machine identifier (`/etc/machine-id`).
- Read files and syscalls directly rather than shelling out where possible; where a command is unavoidable, use a fixed path and fixed arguments.
- Parsing separated from reading so it can be unit tested with fixture files taken from each distribution in the fleet ([DEC-01](../../decisions/0001-fleet-profile.md)).
- Each collector has a time limit so a hung read cannot stall the agent.

### Acceptance criteria

- [ ] Fixture-based tests pass for each fleet distribution
- [ ] Removing or corrupting a source file yields a null field plus a warning and the rest of the report is intact
- [ ] Output on the test VM matches `hostnamectl` and `free` (manual check recorded for AC-1.3)

## P1-A05: Disk and network collectors

### Scope

- Disks: size and free space per real mount, from `/proc/self/mounts` and `statvfs`. Exclude pseudo and virtual filesystems (`proc`, `sysfs`, `tmpfs` and similar, container overlays) using a documented rule; ignore mounts hidden by an overmount; de-duplicate bind mounts of the same device.
- Network: addresses of interfaces that are up and not loopback, IPv4 and IPv6, excluding link-local and container bridge interfaces by documented rule; mark the interface carrying the default route (`/proc/net/route`) as primary.
- Mount and interface lists are stable fields, free space is volatile ([DEC-07](../../decisions/0007-snapshots-and-retention.md)).
- The exclusion and primary-interface rules are documented in [`agent/README.md`](../../../agent/README.md#collected-facts). Network filesystems are not reported (their space belongs to another machine). Without an IPv4 default route, the IPv6 default route (`/proc/net/ipv6_route`) marks the primary interface. A list that could be read only in part (one mount's `statvfs` failed, no routing table) keeps the entries that were read and adds a warning.
- Fixture-based parsing tests, including unusual mount options and names with spaces or escapes.

### Acceptance criteria

- [ ] Disk figures match `df` on the test VM within rounding
- [ ] The primary address matches the VM's routing table
- [ ] Mount names with spaces or unusual escapes are handled
