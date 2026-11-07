# Agent configuration reports: what the agent reads and how to check it

The agent sends a configuration report ([FR-2.1](../backlog/specs/p2-agent-facts.md), `POST /api/v1/reports/config`) to the server: the value of each configuration fact in the server's manifest ([config-facts.md](config-facts.md)), or the reason it could not give one. This page says what the agent reads for each fact, how to see what it reported, and what the states mean.

The agent runs as root under the systemd sandbox ([`agent/contrib/README.md`](../../agent/contrib/README.md)): it can read configuration files, but it has no network administration capability, writes nothing outside its state directory, and never reads password hashes, private keys, or file contents beyond the settings listed here.

## When it reports

- once at startup;
- every 6 hours, less up to 10% (set `[config_report] interval_seconds` in `/etc/fleet-agent/config.toml`; allowed 300 to 86400 seconds);
- once when an operator asks for a report from the dashboard (the server puts `report_request` in the heartbeat responses; the agent sends one report, not one per heartbeat);
- once more, at once, when the server's answer names a newer manifest than the report used.

Each report starts with a conditional fetch of the manifest (`GET /api/v1/manifest/config` with the previous `ETag`). If the server cannot be reached for that, the agent uses the manifest it has; with none, it waits and retries. A report that fails to send is retried with the same `report_id`, so the server discards a duplicate. A report the server rejects for its content is logged with the server's message and not retried.

The agent never runs anything the manifest names. The manifest lists keys, file paths, and unit names; the agent has a fixed reader for each key it knows, and it reports every other key as `unsupported`.

## What each fact is read from

| Facts | Read from | Notes |
|---|---|---|
| `sshd.*` (20) | `sshd -T` (`/usr/sbin/sshd`), 10 second limit | The effective values, not the file. Lists are split on commas; `without-password` is reported as `prohibit-password`. Without `sshd`, all are `unreadable`. |
| `login_defs.*` (5), `useradd.inactive` | `/etc/login.defs`, `/etc/default/useradd` | The last assignment wins, as in `shadow`. A setting that is not set is `unreadable` ("not set") rather than a guessed default; `useradd.inactive` is `-1` when absent, which is `useradd`'s own default. |
| `pwquality.*` (8) | The `pam_pwquality.so` line in `/etc/pam.d/common-password`, then `/etc/security/pwquality.conf.d/*.conf`, then `/etc/security/pwquality.conf` | A PAM option wins over the files, and later drop-ins (by name) over earlier. `retry` comes from the PAM line only. A `conf=` option makes them all `unreadable`, since the agent does not follow it. Without `pam_pwquality` set up, they are `unreadable`. |
| `auto_updates.installed`, `.enabled` | `/usr/bin/unattended-upgrade` exists; `apt-config dump`; `systemctl show` of `apt-daily.timer` and `apt-daily-upgrade.timer` | `enabled` needs both periodic settings above 0 and both timers active and enabled. |
| `firewall.backend`, `.enabled` | `systemctl show` of `ufw`, `firewalld`, `nftables`, `iptables`; `/etc/ufw/ufw.conf` | The first mechanism that is present and enabled, else the first present, else `none`. See "Firewall" below. |
| `services.running`, `services.enabled` | `systemctl list-units`, `systemctl list-unit-files` | Service units only, sorted, bounded. |
| `users.*` (3) | `/etc/passwd`, `/etc/group` | Names only; a line that does not parse makes all three `unreadable`. A shell of `nologin`, `false`, `sync`, `shutdown`, or `halt` is not login-capable. |
| `file:<path>` | `stat` only | `{mode, owner, group}`; `null` for a file that does not exist. `/etc/shadow`, `/etc/gshadow`, and other secret paths are never opened, and the test suite asserts it. Paths that are not canonical absolute paths are `unsupported`. |
| `service:<unit>` | `systemctl show` | `{active, enabled}`; `null` for a unit that does not exist. Unit names are validated before use and passed after `--`. |

## The three states

- `ok`: the agent read the value, and it satisfies the manifest's type and limits.
- `unreadable`: the agent has a reader, but it could not read this now. The `reason` says why (permission denied, command missing, timed out, parse error, not set, value over the manifest's limit). A value outside the limits is reported `unreadable`, never cut to fit, because a cut value would be a wrong value.
- `unsupported`: the agent has no reader for this key (or for this type), or refused the path or unit name. The server accepts it and the dashboard shows it, so adding a fact to the manifest never needs an agent release first.

No fact is ever left out. A report that is over the server's size limit turns the largest list facts to `unreadable` until it fits.

## Seeing what was reported

Server side: the server stores each report as the host's configuration snapshot ([P2-S02](../backlog/specs/p2-config-reports.md)), with every fact's state and reason. Agent side, `journalctl -u fleet-agent` shows one line per report with the reason it was sent, the manifest version, the number of facts, and how many were `unreadable` or `unsupported` (for example):

```
collected the configuration facts reason=startup manifest_version=1 facts=89 unreadable=2 unsupported=0 shrunk=0
config report sent reason=startup attempt=1 request_id=... duplicate=false
```

## Firewall

The agent's unit grants only `CAP_DAC_READ_SEARCH`, so it cannot run `ufw status`, `nft list ruleset`, or `iptables -S`, which need `CAP_NET_ADMIN`. The firewall facts therefore describe what is installed and set to start at boot, from systemd unit state (and `ufw.conf` for ufw). `enabled` for `nftables` or `iptables` means "the unit that loads the rules at boot is enabled", not "rules are loaded right now". A host whose firewall was loaded by hand shows `none`.

## Checking a reader on a real host

Fixtures in `agent/tests/fixtures/facts/debian13/` are modelled on Debian 13 file formats and command output; they were not captured from a running host. After changing a reader, or on a new image, compare the report with the host:

```sh
sshd -T | grep -i -E '^(permitrootlogin|passwordauthentication) '
stat -c '%a %U %G' /etc/ssh/sshd_config
systemctl show ssh.service -p ActiveState -p UnitFileState
```

and then change a setting (for example `PermitRootLogin`), restart `ssh`, ask for a report from the dashboard, and see the value change (AC-2.1).
