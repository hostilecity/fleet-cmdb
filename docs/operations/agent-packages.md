# Agent package reports: what the agent lists and how to check it

The agent sends a package report ([FR-2.3](../backlog/specs/p2-agent-packages.md), `POST /api/v1/reports/packages`, [P2-S08](../backlog/specs/p2-packages.md)) to the server: every installed package with its name, full version (with any epoch), architecture, and source package, and the names of packages it did not list as installed (`skipped`). This page says where the list comes from, which packages count as installed, what `skipped`, `unsupported`, and `unreadable` mean, and how to check a report against the host (AC-2.3).

## When it reports

On the configuration report's cadence (FR-2.3): once at startup, every `[config_report] interval_seconds` (6 hours by default, less up to 10%), and once when an operator asks for fresh reports from the dashboard (the heartbeat's `report_request` names `packages`; one report per request, not one per heartbeat). There is no separate interval setting.

A report that fails to send is retried with the same `report_id` and the same body. One the server rejects for its content is logged and not retried. The body is sent gzip-compressed (`Content-Encoding: gzip`): about 27 KiB for 3,000 packages.

**Stopping.** `systemctl stop fleet-agent` still takes at most about 40 seconds (the inventory loop is the slowest; see [agent-config-facts.md](agent-config-facts.md)). A package listing in progress when the stop arrives is dropped, not sent, and a report waiting for its retry is not sent again; the agent sends a startup report when it starts again.

## Where the list comes from

One command, with fixed arguments, no shell, a cleared environment, a 20 second limit, and an 8 MiB output cap:

```sh
/usr/bin/dpkg-query --show --showformat='${db:Status-Status}\t${Package}\t${Architecture}\t${Version}\t${source:Package}\n'
```

`${source:Package}` is dpkg's own source package name: the `Source` field without its `(version)`, or the package's own name when it has none. The agent first checks that `/var/lib/dpkg/status` exists. Only dpkg is supported ([DEC-01](../decisions/0001-fleet-profile.md)).

## Which packages count as installed

Only a package whose status is `installed` is reported as installed (owner decision, P2-S08):

| dpkg status (`dpkg -l` second letter) | Reported |
|---|---|
| `installed` (`i`) | yes, in `packages` |
| `unpacked` (`U`), `half-installed` (`H`), `half-configured` (`F`), `triggers-awaited` (`W`), `triggers-pending` (`t`): an installation that was interrupted | no: in `skipped`, with the status as the reason (counted as `not_configured` in the journal line) |
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

## Seeing what was reported

`journalctl -u fleet-agent` shows one line per report (for example):

```
listed the installed packages reason=startup manager=dpkg packages=412 skipped=0 skipped_not_named=0 not_configured=0 removed=3 warnings=0 json_bytes=50211 gzip_bytes=6874
package report sent reason=startup attempt=1 request_id=... duplicate=false
```

An `unsupported` or `unreadable` report logs a warning with `unsupported_reason`, each warning is logged too, and so is each skipped package (`package skipped: not reported as installed`, with the package and its reason).

## Checking a report against the host (AC-2.3)

The reported set must equal the host's own listing of installed packages, with no package missing or invented, and the skipped names must be the interrupted installations. On the VM:

```sh
dpkg-query --show --showformat='${db:Status-Abbrev}|${Package}:${Architecture} ${Version}\n' \
  | awk -F'|' 'substr($1, 2, 1) == "i" { print $2 }' | sort > dpkg.txt
dpkg-query --show --showformat='${db:Status-Abbrev}|${Package}\n' \
  | awk -F'|' 'substr($1, 2, 1) ~ /[HUFWt]/ { print $2 }' | sort -u > interrupted.txt
```

and compare them with the host's package list on the dashboard, or with the report (`jq -r '.packages[] | "\(.name):\(.architecture) \(.version)"' | sort`, and `jq -r '(.skipped // [])[].name' | sort -u`). The VM test ([`agent/scripts/vm-test.sh`](../../agent/scripts/vm-test.sh), scenario "Package report matches dpkg-query") does exactly this on Debian's Debian 13 genericcloud image, under the real unit, on every agent change, sources included; the agent's tests do it against the dpkg database of the machine running them.

## Memory

Measured with the test suite's counting allocator (`peak_memory_for_3000_packages_stays_modest`, and `peak_memory_with_the_real_dpkg_query` with the real `dpkg-query` and its reader threads): a synthetic 3,000-package listing (242 KB of `dpkg-query` output, 365 KB of JSON, 27 KB compressed) peaks at about **1.0 MB of heap** (1,018,534 bytes; 1,038,384 with the real command), from the command's output to the compressed body. The output is parsed in place and dropped before the report is encoded, the report is serialized straight into the gzip encoder (the JSON is never held whole), and only the compressed body is kept for a retry. The test fails if the peak passes 2 MiB.

## Fixtures

`agent/tests/fixtures/packages/debian13/status` is a dpkg database modelled on a Debian 13 cloud VM (epochs, `+` and `~` in versions, `+` in names, `libc6` and `libgcc-s1` for `amd64` and `i386`, `all` packages, source packages that differ from the binary, a held package, three interrupted installations (`unpacked`, `half-configured`, `triggers-pending`), a removed one, a purged one); it was not captured from a running host. `dpkg-query-show` next to it is what the real `dpkg-query` prints for it with the agent's arguments, and a test checks that wherever `dpkg-query` exists. A run on a real Debian 13 VM is the AC-2.3 check (the VM test above).
