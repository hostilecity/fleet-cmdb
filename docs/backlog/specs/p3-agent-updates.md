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
