# P2-AGENT-FACTS: Agent configuration facts and report scheduling

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-A01: Agent: manifest consumption, config fact framework, and report scheduling

### Scope

- Fetch the fact manifest from the server and collect the facts it lists. Facts the agent has no reader for are reported as `unsupported` with a reason; the report never silently omits a fact.
- A fact result type of `ok` with a value, `unreadable` with a reason (permission denied, command missing, timeout, parse error), or `unsupported`.
- Build and send the config report (report id, schema version, manifest version, collection time) with the same retry and idempotency behaviour as [P1-A07](p1-agent-report.md).
- Schedule: every 6 hours by default (configurable) and when a heartbeat directive requests a report ([DEC-13](../../decisions/0013-on-demand-reports.md)).
- Collection runs with time limits and a bound on output sizes; the agent never executes anything the manifest names (the manifest lists fact keys only, not commands).
- Delivered as `agent/src/facts/` (the `Host` trait, `RealHost`, the manifest parser, and `collect`) and `agent/src/report/config.rs` (the reporter), with `agent/src/report/requests.rs` for the directive; operator view in [docs/operations/agent-config-facts.md](../../operations/agent-config-facts.md). The manifest is fetched with its `ETag` before each report (a `304` or a failed fetch keeps the cached copy) and parsed defensively: unknown types and bad limits are dropped or defaulted and logged, at most 2000 facts are read, at most 512 `file:` and 512 `service:` facts, paths must be canonical and unit names valid (after `--`), and secret paths are refused by the reader itself. Readers are chosen by key from a fixed table, so a key with no reader, or with a type that differs from the reader's, is `unsupported`; nothing in the manifest becomes a command. Every value is checked against the manifest's type and limits before it is reported, and one outside them is `unreadable` with a reason, never cut (an invalid value would reject the whole report). Commands are absolute paths with fixed arguments, a cleared environment, no shell, a time limit and an output cap, inside a 60 second budget for a collection; file reads run on bounded threads (5 seconds each) and share that budget, none starting once it is used up, so a manifest of paths on a dead mount cannot hold a collection or shutdown much past it. The report is sent at startup, every `[config_report] interval_seconds` (default 21600, minus up to 10% jitter; the server does not direct it yet, so `min_seconds` and `max_seconds` only bound a later directive), and on `directives.report_request.types`. One request raises one report per episode: a run of accepted heartbeats carrying the type, ended by a response without it (a failed heartbeat changes nothing), so a request repeated on every heartbeat for up to an hour gives one report. The directive carries no request id, so an episode also ends once the report sent for it is accepted: a heartbeat sent after that which still lists the type carries a new request (the server allows one five minutes after the last, sooner than a ten-minute heartbeat may bring a response without the type), while one sent before it raises nothing. A report lost to the network is retried with its `report_id`; a lost or rejected requested report is not repeated, and the request expires on the server. When the server's response names a newer `manifest_version`, the agent refetches and rebuilds only if the manifest it got is newer than the one used, so a server ahead of its own endpoint cannot make it loop. The body is kept under 1,000,000 bytes by turning the largest list facts `unreadable` (there is no compression). `inventory` in the same directive gives one extra inventory report; `packages` was logged as ignored until #27 added the package collector ([P2-AGENT-PACKAGES](p2-agent-packages.md)), which answers it with one package report.

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
- Delivered as `facts/sshd.rs`, `facts/policy.rs`, and `facts/updates.rs`. The 20 `sshd.*` facts come from `sshd -T` (10 second limit, 1 MiB of output), each converted to the manifest's type and refused if it does not fit; without `sshd` they are all `unreadable` with the reason, and the config file is never parsed instead. `login_defs.*` use the last assignment as `shadow` does, with C integer syntax (octal and hex) and quotes stripped; `pwquality.*` are read as libpwquality reads them, a later setting winning: `pwquality.conf.d/*.conf` in name order, then `pwquality.conf` (so the main file overrides the drop-ins), then options on the PAM line, with `retry` from the PAM line only and a `conf=` option making them `unreadable`. A setting that is not set anywhere is `unreadable` ("not set") rather than a built-in default that may change between releases; the one exception is `useradd.inactive`, which is -1 when the file or key is absent, the default `useradd` documents. `auto_updates.installed` is `/usr/bin/unattended-upgrade` existing; `enabled` needs, in `apt-config dump`, `APT::Periodic::Enable` not 0 (absent is on) and `Update-Package-Lists` and `Unattended-Upgrade` set to run (`always`, or above 0 with an optional `s`, `m`, `h`, or `d` unit), and both apt timers active with `UnitFileState=enabled` (`enabled-runtime`, `static`, `alias`, and `generated` do not prove a unit starts at boot). The fixtures (`agent/tests/fixtures/facts/debian13/`) are modelled on Debian 13 and were not captured from a host; that check is left for the VM run (see the open questions on the pull request).

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
- Delivered as `facts/firewall.rs`, `facts/systemd.rs`, `facts/users.rs`, and `facts/files.rs`. The agent's unit grants only `CAP_DAC_READ_SEARCH`, so `ufw status`, `nft list ruleset`, and `iptables -S` cannot run (they need `CAP_NET_ADMIN`); the firewall facts instead come from systemd unit state of `ufw`, `firewalld`, `nftables`, and `iptables` plus `/etc/ufw/ufw.conf`: the first mechanism present and enabled, else the first present, else `none`, so "enabled" for nftables and iptables means "set to load at boot", not "rules loaded now". Services use `systemctl list-units` and `list-unit-files` (service units only, bounded and sorted, names kept as systemd prints them, escaped ones included; the stricter unit-name check applies only to names from the manifest that go into a command), and `service:<unit>` facts use `systemctl show` in chunks of 40 units. Users come from `/etc/passwd` and `/etc/group`, names only; a malformed line makes the three `users.*` facts `unreadable`, and a shell of `nologin`, `false`, `sync`, `shutdown`, or `halt` is not login-capable. `file:<path>` facts are `stat` only (following symlinks); a missing file is `null`, an unreadable one `unreadable`, and owner and group fall back to the number when there is no name. A test asserts `/etc/shadow` is only `stat`ed and that no secret material is in any fixture report. Missing command, permission denied, timeout, too much output, and running out of the collection's time each give a reason (`facts/tests.rs`, "failure modes").

### Acceptance criteria

- [ ] Values match manual inspection on the test VM
- [ ] Shadow file contents are never read (test asserts the reader opens only `stat` on it)
- [ ] Each failure mode (missing command, permission denied, timeout) yields a reason, not a crash
