# Agent package reports: what the agent lists and how to check it

The agent sends a package report ([FR-2.3](../backlog/specs/p2-agent-packages.md), `POST /api/v1/reports/packages`, [P2-S08](../backlog/specs/p2-packages.md)) to the server: every installed package with its name, full version (with any epoch), architecture, and source package, and the names of packages it did not list as installed (`skipped`). This page says where the list comes from, which packages count as installed, what `skipped`, `unsupported`, and `unreadable` mean, and how to check a report against the host (AC-2.3).

## When it reports

On the configuration report's cadence (FR-2.3): once at startup (after a restart, following a random delay of up to 10 minutes, drawn apart from the config report's), every `[config_report] interval_seconds` (6 hours by default, less up to 10%), and once when an operator asks for fresh reports from the dashboard (the heartbeat's `report_request` names `packages`; one report per request, not one per heartbeat). There is no separate interval setting.

A report that fails to send is retried with the same `report_id` and the same body. One the server rejects for its content is logged and not retried. The body is sent gzip-compressed (`Content-Encoding: gzip`): about 27 KiB for 3,000 packages.

**Stopping.** `systemctl stop fleet-agent` still takes at most about 40 seconds (the inventory loop is the slowest; see [agent-config-facts.md](agent-config-facts.md)). A package listing in progress when the stop arrives is dropped, not sent, and a report waiting for its retry is not sent again; the agent sends a startup report when it starts again.

## Where the list comes from

One command, with fixed arguments, no shell, a cleared environment, a 20 second limit, and an 8 MiB output cap:

```sh
/usr/bin/dpkg-query --show --showformat='${db:Status-Status}\t${Package}\t${Architecture}\t${Version}\t${source:Package}\n'
```

`${source:Package}` is dpkg's own source package name: the `Source` field without its `(version)`, or the package's own name when it has none. The agent first checks that `/var/lib/dpkg/status` exists. Only dpkg is supported ([DEC-01](../decisions/0001-fleet-profile.md)).

## Which packages count as installed

A package whose status is `installed`, `triggers-awaited`, or `triggers-pending` is reported as installed; an interrupted installation is not (owner decision, P2-S08):

| dpkg status (`dpkg -l` second letter) | Reported |
|---|---|
| `installed` (`i`) | yes, in `packages` |
| `triggers-awaited` (`W`), `triggers-pending` (`t`): installed and configured, a trigger has not run yet | yes, in `packages` (apt and `dpkg -l` count it as installed) |
| `unpacked` (`U`), `half-installed` (`H`), `half-configured` (`F`): an installation that was interrupted | no: in `skipped`, with the status as the reason (counted as `not_configured` in the journal line) |
| `config-files` (`c`): removed, only its configuration files left | no |
| `not-installed` (`n`): purged | no (dpkg does not list it) |

The selection state does not matter: a package on hold (`hi`) is installed and reported. An interrupted installation is neither installed nor removed: the server keeps it apart as "Skipped / incomplete" (a package that was installed before and is now skipped is not shown as removed). A skipped package is named once for all its architectures. At most 64 are named; with more, the rest are counted in one warning.

## `unsupported` and `unreadable`

Both reports list no packages and give a reason (in the `unsupported_reason` field, whose name the contract kept). The server treats the set as unknown, never as "no packages", and keeps what it knew before an `unreadable` report.

`manager: unsupported` is a host the agent has no reader for:

- there is no dpkg database (the reason names `rpm` or `apk` if one is found).

`manager: unreadable` is a host with dpkg whose packages could not be listed (owner decision):

- `dpkg-query` is missing, fails, times out, or prints more than 8 MiB (the reason quotes the first line of its error);
- `/var/lib/dpkg/status` exists but cannot be read;
- the list is larger than a report may carry: more than 20,000 packages, more than 4,000,000 bytes of JSON, or more than 1,000,000 bytes compressed (the server's limits are 20,000, 4 MiB, and 1 MiB). It is not sent in part, because a shorter list would read as removed packages.

## Warnings

A line the contract cannot carry is left out with a warning (`field: packages`), and the rest is still reported: a name, version, or architecture outside the contract's patterns, a status dpkg does not define, a line that is not five fields or not UTF-8, or the same name and architecture listed twice (the first is kept). A source name outside the contract's pattern is reported as `null` with a warning. Values are never cut to fit. At most 64 warnings are sent; the last then counts the rest. On a normal Debian host there are none.

When the package name of such a line is readable (the version, the architecture, or the status is the problem), the package is also named in `skipped` with a short reason, so the server shows it as skipped and not as removed. A line without a readable name (a bad name, the wrong number of fields, not UTF-8) is a warning only. The server stores the reported set as the host's whole set, so a package that is neither listed nor named would show as removed.

One thing the server does not do yet (P2-S11): a skipped package is not in the stored set, so its vulnerability findings are resolved as removed and reopen when the package is listed again.

## What is in use (FR-2.6)

With a dpkg listing the report also says what running processes use (`in_use`, [VT-APPLICABILITY](../backlog/specs/vt-applicability.md)), for the vulnerability triage rules L1 and N4. It names binary packages and classes only, never a process id, command line, user name, address, or port.

**Listening and running services, always, with no extra privilege.** The agent reads the listening TCP and bound UDP sockets from `/proc/net/{tcp,tcp6,udp,udp6}`, asks the kernel's `sock_diag` netlink interface for each socket's cgroup (what `ss --cgroup` shows), finds the cgroup's directory under `/sys/fs/cgroup` (its inode number is the id), and from its path the systemd service (only inside `system.slice`). A socket systemd itself holds for socket activation (in `init.scope`, or in the socket unit's own cgroup) is matched with `systemctl list-sockets`. The services' executables come from `systemctl show --property=Id,ExecStart`, and their packages from dpkg's file lists under `/var/lib/dpkg/info/` (a path is looked up on both sides of the `/usr` merge). The report has:

- `listening`: each package with `network` (any socket on a non-loopback address, the wildcard included) or `loopback` (127.0.0.0/8 or ::1 only);
- `services`: the packages of the running services' executables;
- `unnamed_listeners`: sockets counted but not named: a container, a user session, the kernel, or a service whose executable no package owns (for example under `/opt`).

**These lists only say what is used, never what is not.** A service is named by the package of the command in its `ExecStart=`. When that command is a wrapper, the wrapper's package is named and the program it starts is not: Debian's PostgreSQL service runs `pg_ctlcluster`, so a PostgreSQL server listening on the network shows as `postgresql-common` `network`, and `postgresql-17` is in neither list. The same goes for `/bin/sh -c`, `env`, and interpreters (`python3`, `java`). Naming the program itself would need `/proc/<pid>/exe` of other users' processes, which the agent's unit cannot read without a new privilege. So the server never treats a package as idle because it is missing from these lists.

All of it is readable under the agent's unit as it is; the unit does not change. If the sockets, their cgroups, systemd's list of sockets it holds for socket activation, the services, or the file lists cannot be read whole, `in_use` is `null` with a warning (`field: in_use`), so no package looks idle. Only `system.slice` and `init.scope` are walked under `/sys/fs/cgroup`. Sockets systemd holds are read with `systemctl list-sockets --show-types`. Limits: 10,000 sockets, 1,000 services, 20,000 cgroups under those two, `/proc/net` files up to 32 MiB, file lists up to 64 MiB each, 10 seconds.

**The library-use scan, only where the VM enables it.** With

```toml
[packages]
library_scan = true
```

in `/etc/fleet-agent/config.toml` (and `systemctl restart fleet-agent`), package reports also carry the result of `fleet-agent-library-scan.service`: a transient unit the agent starts with `systemd-run`, which runs the agent's own binary as `fleet-agent library-scan`. **It runs at most once an hour**, however often a report is asked for (by the schedule, the dashboard's "fresh reports", or the `refresh_reports` task), and across agent restarts and updates: the last scan's time and result are kept in `/var/lib/fleet-agent/library-scan.json` (readable by root only). Reports in between carry the last result, or the last failure, with its time (`scanned_at`). A record more than an hour old by the clock (after a suspend), or one that is damaged, means a new scan; deleting the file makes the next report scan again. It reads every process's `/proc/<pid>/maps` (at most 4,096 processes, 50,000 mapped files under `/usr`, `/bin`, `/sbin`, and `/lib*`, and 50,000 elsewhere, within 25 seconds), maps the files to packages, and reports:

- `libraries`: each package with a file mapped by a running process, `stale` when a process still maps a deleted version of one of its files (it runs old code until restarted);
- `native`: the packages the scan can judge. Python, Perl, Ruby, Node, and Java read their code rather than map it, and a shell script runs as `dash`, so a package of such code can be in use with nothing of it in any map. A package counts as native only when it ships an ELF executable or shared library under `/usr`, `/bin`, `/sbin`, or `/lib*`, no ELF file elsewhere (code under `/opt` is not judged), no interpreted code (a `.py`, `.pyc`, `.pyo`, `.pyz`, `.pm`, `.pl`, `.rb`, `.js`, `.mjs`, `.cjs`, `.jar`, `.class`, `.war`, `.beam`, `.php`, `.lua`, `.tcl`, `.sh`, or `.bash` file outside `/usr/share/doc`), and no `#!` script anywhere (an executable file, a file named like code, or the target of one of its symlinks), and the scan could read all its files. So a daemon with an init script or a cron job is never native. Nor is a package of code that runs only on demand: anything with a file in a PAM `security/`, `sasl2/`, `gconv/`, `pkcs11/`, `ossl-modules/`, `engines-3/`, `engines-1.1/`, `krb5/plugins/`, `gio/modules/`, `gdk-pixbuf-2.0/`, or GTK `modules/` directory, a `libnss_*` file, or a set-user-ID or set-group-ID program such as `unix_chkpwd` (these are mapped only while someone logs in or a lookup runs). Nor is a package that ships a D-Bus activation file, a systemd timer, or a cron entry, or whose program one of those starts: the scan reads the `Exec=` of D-Bus activation files, the services timers start, `/etc/crontab`, `/etc/cron.d`, and the users' crontabs it can read. A user's own crontab is usually private to them, so a program only it runs can still look idle. A file several packages list (a diversion) counts as used by each of them, and a package's lists for every architecture count together. A package whose code is reached through a directory symlink (other than the `/usr` merge), or whose file list has a name that is not valid UTF-8, is not judged. If the scan runs out of its 25 seconds, it fails rather than judge on part of a package.

`complete` is then `true`. **Only a package in `native` and not in `libraries` is ever called idle** (rule L1, owner decision 2026-11-20); without the scan, nothing is. "Idle" is as of the scan: a program a service runs now and then (`curl`, `convert`) looks idle between runs. The server stops relying on a scan once the host's latest package report arrived more than 12 hours ago, or arrived more than an hour after (or before) it was collected, or the scan ran more than 2 hours before that report was collected or more than 5 minutes after it.

Reading other processes' maps needs `CAP_SYS_PTRACE`. The scan unit has that capability alone, no network (`PrivateNetwork=yes`, `IPAddressDeny=any`), a read-only filesystem with home directories and the agent's config and state hidden, only the process entries of `/proc` (`ProcSubset=pid`), no input but its mode, its result on a pipe, and at most 30 seconds (`RuntimeMaxSec=30`). The agent's own unit never has the capability ([threat model](../decisions/phase-3-threat-model.md) F-13); the `apply_package_updates` task units and `fleet-agent-rollback.service` run with every capability by design, but read no process's maps. A scan that fails is reported as `library_scan: failed` with a warning; the services are still reported. To see a run: `journalctl -u fleet-agent-library-scan`.

## Seeing what was reported

`journalctl -u fleet-agent` shows one line per report (for example):

```
listed the installed packages reason=startup manager=dpkg packages=412 skipped=0 skipped_not_named=0 not_configured=0 removed=3 warnings=0 json_bytes=50211 gzip_bytes=6874
package report sent reason=startup attempt=1 request_id=... duplicate=false
```

An `unsupported` or `unreadable` report logs a warning with `unsupported_reason`, each warning is logged too, and so is each skipped package (`package skipped: not reported as installed`, with the package and its reason).

On the server, a host's packages are stored as a package set shared with every host and snapshot that has the same list, in chunks (ADR 0028). Reading the database by hand: `host_package_sets.package_set_id` names the host's set, `package_sets.chunk_ids` its chunks, and `package_chunk_entries` their packages; `bin/rails runner 'puts PackageStore.packages(HostPackageSet.find_by!(host_id: ID).package_set_id).map(&:to_a).inspect'` prints a host's list.

## Checking a report against the host (AC-2.3)

The reported set must equal the host's own listing of installed packages, with no package missing or invented, and the skipped names must be the interrupted installations. On the VM:

```sh
dpkg-query --show --showformat='${db:Status-Abbrev}|${Package}:${Architecture} ${Version}\n' \
  | awk -F'|' 'substr($1, 2, 1) == "i" { print $2 }' | sort > dpkg.txt
dpkg-query --show --showformat='${db:Status-Abbrev}|${Package}\n' \
  | awk -F'|' 'substr($1, 2, 1) ~ /[HUF]/ { print $2 }' | sort -u > interrupted.txt
```

and compare them with the host's package list on the dashboard, or with the report (`jq -r '.packages[] | "\(.name):\(.architecture) \(.version)"' | sort`, and `jq -r '(.skipped // [])[].name' | sort -u`). The VM test ([`agent/scripts/vm-test.sh`](../../agent/scripts/vm-test.sh), scenario "Package report matches dpkg-query") does exactly this on Debian's Debian 13 genericcloud image, under the real unit, on every agent change, sources included; the agent's tests do it against the dpkg database of the machine running them.

## Memory

Measured with the test suite's counting allocator (`peak_memory_for_3000_packages_stays_modest`, and `peak_memory_with_the_real_dpkg_query` with the real `dpkg-query` and its reader threads): a synthetic 3,000-package listing (242 KB of `dpkg-query` output, 365 KB of JSON, 27 KB compressed) peaks at about **1.0 MB of heap** (1,018,534 bytes; 1,038,384 with the real command), from the command's output to the compressed body. The output is parsed in place and dropped before the report is encoded, the report is serialized straight into the gzip encoder (the JSON is never held whole), and only the compressed body is kept for a retry. The test fails if the peak passes 2 MiB.

## Fixtures

`agent/tests/fixtures/packages/debian13/status` is a dpkg database modelled on a Debian 13 cloud VM (epochs, `+` and `~` in versions, `+` in names, `libc6` and `libgcc-s1` for `amd64` and `i386`, `all` packages, source packages that differ from the binary, a held package, two interrupted installations (`unpacked`, `half-configured`), a package with a trigger pending (`triggers-pending`, installed), a removed one, a purged one); it was not captured from a running host. `dpkg-query-show` next to it is what the real `dpkg-query` prints for it with the agent's arguments, and a test checks that wherever `dpkg-query` exists. A run on a real Debian 13 VM is the AC-2.3 check (the VM test above).
