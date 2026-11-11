# P3-AGENT-UPDATES: Agent task: apply_package_updates

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- Implements the [DEC-16](../../decisions/0016-package-update-policy.md) policy for `apt` on Debian 13 ([DEC-01](../../decisions/0001-fleet-profile.md)): update index, then upgrade only (no removals, no distribution upgrade), non-interactive, keep local configuration, respect holds, bounded wait for the package manager lock.
- Fixed command vectors; the only task parameter is the validated `scope`, if adopted.
- Detects whether a reboot is needed and reports `reboot_required` in structured details; never reboots, never restarts services.
- On success, triggers an immediate package report ([P2-A04](p2-agent-packages.md)) so the dashboard reflects the new versions.
- Long timeout, graceful terminate on timeout with the repair guidance in the reported reason ([DEC-16](../../decisions/0016-package-update-policy.md)); not interruptible once running.
- Captured output is bounded and truncated with a marker.

## Acceptance criteria

- [ ] AC-3.4: on a test VM, running the task updates packages, reports success with output, and the next package report shows the new versions
- [ ] No reboot occurs, and `reboot_required` is reported when applicable
- [ ] Lock contention produces a clear failure rather than a hang
- [ ] A forced timeout terminates the process tree and reports `timed_out` (on a disposable VM)

## As built (#37)

- `agent/src/tasks/apply_updates.rs` (the job) and `apply_updates/apt.rs` (Debian's adapter, `Manager`; another package manager is another implementation, issue #163). Registered in `Registry::production` and `tasks::IMPLEMENTED`; still off unless the VM's `[tasks] enabled` lists it (DEC-14).
- **Steps.** In the agent: list the installed packages (dpkg), wait up to 5 minutes while another process holds a lock of apt or dpkg (`fcntl` probe of `/var/lib/dpkg/lock-frontend`, `/var/lib/dpkg/lock`, `/var/lib/apt/lists/lock`, `/var/cache/apt/archives/lock`), else `lock_timeout` with nothing run. Then four transient units: (1) `apt-get -q --error-on=any -o DPkg::Lock::Timeout=300 update`; (2) `apt-get -q -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o APT::Get::Upgrade-Allow-New=false --no-remove upgrade`; (3) `apt-get -q --simulate -o APT::Ignore-Hold=true -o APT::Get::Upgrade-Allow-New=true upgrade`, which changes nothing, for what was held back (its `Inst` lines, and its kept-back list for upgrades that would need a removal; left out if its output was cut); (4) `needrestart -b -r l` when installed. A step failing with apt's lock error (an `E:` line, not the `Waiting for cache lock` lines apt prints while it waits) is `lock_timeout`, otherwise `nonzero_exit`. No program starts after the deadline, and a package listing is skipped when less time is left than its own 20-second limit.
- **Result.** Details: `reboot_required` (`/run/reboot-required`, an upgraded `linux-image-*`, or needrestart's kernel status), `services_needing_restart` (needrestart, when installed), and two new keys, `packages_upgraded` (count, from dpkg before and after) and `packages_held_back` (names), which the server now keeps (P3-S04, a scope addition for the approved task detail mockup's "14 upgraded, 1 held back"). The output has a `$ <program>` line before each step and a summary at the end. A package report is requested once the upgrade has started, however it ends.
- **Never reboots, never restarts services:** `NEEDRESTART_MODE=l` in the fixed environment keeps needrestart's apt hook to listing (threat model D7). Packages' own maintainer scripts restarting their daemon is normal Debian behaviour (threat model Q6, open).
- **Deadline:** the catalog's 60 minutes (or the server's lower one); the unit is stopped and the output says to run `dpkg --configure -a`, as does a failed upgrade or an update refused because dpkg was interrupted. The task never runs it itself.
- **Agent restart (threat model L8):** the units run on; the restarted agent decides from their exits (`TaskImpl::recovered`): an upgrade that ended with 0 is `succeeded` with `reboot_required` from the flag file, where #35 reported `interrupted`.
- **Unit properties** reviewed for real upgrades (`docs/operations/agent-task-privileges.md`): `SystemCallArchitectures=native` removed (multiarch triggers), the three environment variables added.
- **Tests:** `apply_updates/tests.rs` (a fake apt: scripted units and host), `apt.rs` (vectors and parsers), privilege smoke (the simulation in a real unit; the lock probe and the listing inside the sandbox), and `scripts/vm-test.sh` scenarios 370 to 373 on Debian 13 against a local repository built in the guest.
