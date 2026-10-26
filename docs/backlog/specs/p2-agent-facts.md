# P2-AGENT-FACTS: Agent configuration facts and report scheduling

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-A01: Agent: manifest consumption, config fact framework, and report scheduling

### Scope

- Fetch the fact manifest from the server and collect the facts it lists. Facts the agent has no reader for are reported as `unsupported` with a reason; the report never silently omits a fact.
- A fact result type of `ok` with a value, `unreadable` with a reason (permission denied, command missing, timeout, parse error), or `unsupported`.
- Build and send the config report (report id, schema version, manifest version, collection time) with the same retry and idempotency behaviour as [P1-A07](p1-agent-report.md).
- Schedule: every 6 hours by default (configurable) and when a heartbeat directive requests a report ([DEC-13](../../decisions/0013-on-demand-reports.md)).
- Collection runs with time limits and a bound on output sizes; the agent never executes anything the manifest names (the manifest lists fact keys only, not commands).

### Acceptance criteria

- [ ] A fact with no reader appears as `unsupported`, not absent
- [ ] A directive causes one extra report and then no more
- [ ] A hostile manifest (unknown keys, huge lists) is bounded and never causes command execution

## P2-A02: Agent facts: SSH settings, login and password policy, automatic updates

### Scope

- SSH server settings: effective values (for example via `sshd -T` with fixed arguments and a time limit), reported per key; if the command cannot run, report the facts as unreadable with the reason rather than guessing from the config file.
- Login and password policy: `/etc/login.defs` values and password quality settings (`pwquality` configuration) per the manifest.
- Automatic updates: whether the distribution's mechanism is installed and enabled (`unattended-upgrades` and its apt timers on Debian 13, [DEC-01](../../decisions/0001-fleet-profile.md)).
- Parsers separated from readers; fixture tests from each fleet distribution.
- Reads configuration only; never reads or reports password hashes, keys, or file contents beyond the listed settings.

### Acceptance criteria

- [ ] Changing `PermitRootLogin` on the test VM and re-reporting changes the reported value (AC-2.1 manual check)
- [ ] When `sshd` is absent, the facts are unreadable with a reason
- [ ] No secret material appears in any report (test over fixtures)

## P2-A03: Agent facts: firewall, services, local users, sensitive file permissions

### Scope

- Firewall: detect which mechanism is present (for example `ufw`, `firewalld`, `nftables`, `iptables`) and report backend and enabled state; read-only commands with fixed arguments.
- Services: running and enabled systemd units (on non-systemd distributions per [DEC-01](../../decisions/0001-fleet-profile.md)); bounded list size.
- Local users: name, uid, home, and login shell from `/etc/passwd`, flagged as login-capable or not. Never read or report `/etc/shadow` contents.
- Sensitive file permissions for the manifest's file list: mode, owner, and group via `stat` only; a missing file is reported as missing, an unreadable one as unreadable.
- Parser and reader separation with fixtures.

### Acceptance criteria

- [ ] Values match manual inspection on the test VM
- [ ] Shadow file contents are never read (test asserts the reader opens only `stat` on it)
- [ ] Each failure mode (missing command, permission denied, timeout) yields a reason, not a crash
