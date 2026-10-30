# fleet-agent

The Fleet CMDB agent: a single static Rust binary that runs as a systemd service on each VM and reports host facts to the server (FR-1.6). The fleet is Debian 13 on x86_64 ([DEC-01](../docs/decisions/0001-fleet-profile.md)), so the only release target is `x86_64-unknown-linux-musl`. The agent runs as root under a hardened unit ([DEC-03](../docs/decisions/0003-agent-privilege.md)).

Status: Phase 1 in progress. Config, logging, the state directory, the HTTPS client, and the retry policy are in place (P1-AGENT-CORE), and so are the read-only fact collectors (P1-AGENT-COLLECT) and heartbeats and inventory reports (P1-AGENT-REPORT); `run` reports until it gets a stop signal. `install` and `uninstall` arrive with P1-AGENT-INSTALL.

## Build and check

The toolchain is pinned in `rust-toolchain.toml`, and rustup installs it, the musl target, rustfmt and clippy on first use.

```sh
cd agent
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/fleet-agent   # "statically linked" (or "static-pie linked")
target/x86_64-unknown-linux-musl/release/fleet-agent --version
```

Building the musl target from macOS needs a cross linker. The simplest route is to build inside a Linux container or rely on CI, which uploads the binary as a workflow artefact on every push to `main`.

`--version` prints the agent version (from `Cargo.toml`) and the agent schema version, the integer `schema_version` sent with reports ([DEC-08](../docs/decisions/0008-api-conventions.md)):

```
fleet-agent 0.1.0 (agent schema 1)
```

## Commands

```
fleet-agent [run] [--config PATH]          run the agent (the default command)
fleet-agent check-config [--config PATH]   validate the config and trusted certificates; never contacts the server
fleet-agent install [OPTIONS]              install, enroll, and start the agent (see below)
fleet-agent uninstall [--keep-state]       stop and remove the agent (see below)
fleet-agent --version | --help
```

The config path defaults to `/etc/fleet-agent/config.toml`. Exit status of `run` and `check-config`: `0` success, `2` usage error, `78` (`EX_CONFIG`) invalid, missing, or unreadable config, `1` any other startup failure. A server outage never makes the agent exit.

## Install, onboarding, and uninstall

One command, run as root on a Debian 13 x86_64 VM with the downloaded binary ([P1-AGENT-INSTALL](../docs/backlog/specs/p1-agent-install.md), [ADR 0017](../docs/decisions/0017-agent-onboarding.md)):

```sh
sudo ./fleet-agent install --server https://agent.example.lan
```

It prints each step and, on any failure, what happened and what to do next:

1. **Checking this VM.** Root, Debian 13 on x86_64 ([DEC-01](../docs/decisions/0001-fleet-profile.md)), systemd, every path it would touch is safe, and the server answers as the agent API with a certificate this VM trusts (add `--ca-file PATH` for a private certificate authority; it is copied to `/etc/fleet-agent/ca.pem`). Nothing is changed until these pass.
2. **Installing.** The binary goes into the side-by-side layout from [P1-PACKAGING](../docs/backlog/specs/p1-packaging.md) and [ADR 0018](../docs/decisions/0018-signed-agent-updates.md), and the systemd unit built into the binary (`src/install/fleet-agent.service`) is written:

   ```
   /usr/lib/fleet-agent/versions/<version>/fleet-agent    mode 0755
   /usr/lib/fleet-agent/current  -> versions/<version>
   /usr/lib/fleet-agent/previous -> versions/<older>    after an upgrade; older versions are removed
   /usr/bin/fleet-agent -> ../lib/fleet-agent/current/fleet-agent
   /etc/systemd/system/fleet-agent.service
   ```

3. **Enrolling.** By default it starts onboarding: it prints the approval page, the user code (for example `WDJB-MJHT`), and on a terminal a QR code of the page, then waits with a countdown while an operator approves the VM in the dashboard. With a one-time token from pre-registration it enrolls with no person present: `--token` asks for the token with the input hidden, `--token-stdin` reads it from standard input, and `FLEET_ENROLLMENT_TOKEN` is read from the environment. The token is never accepted on the command line (`--token VALUE` is refused), so it cannot appear in the process list or shell history. The credential is written only once received, to `/etc/fleet-agent/config.toml` (directory `0700`, file `0600`, written atomically with the mode set before any content).
4. **Starting.** A heartbeat with the new config confirms the server accepts the credential, then `fleet-agent.service` is enabled, (re)started, and watched until it stays running. The summary names the host as approved, the version, the service state, and where the logs are (`journalctl -u fleet-agent`).

**Re-running is safe.** On an enrolled VM the same command keeps the credential (and every setting in the config) and repairs or upgrades the installation: a newer binary becomes `current` and the old one `previous`, and the service restarts only if something changed. This is the manual upgrade (NFR-4). `--server` may be left out on a re-run. `--reenroll` starts onboarding again for a lost or revoked credential, keeping the other settings; `--token` re-enrolls with a new one-time token. A failed or interrupted install leaves the previous config, or none, never a partial one, and the next run removes any temporary files a killed run left. Two installers cannot run at once (a lock on `/usr/lib/fleet-agent`).

**Uninstall.** `sudo fleet-agent uninstall` stops and disables the service, removes the unit, `/usr/bin/fleet-agent`, `/usr/lib/fleet-agent`, the config and copied CA certificate (and `/etc/fleet-agent` if nothing else is in it), and `/var/lib/fleet-agent`, then lists what it removed. `--keep-state` keeps the config and state for a reinstall. Anything the installer did not create (a unit without its header, another file at `/usr/bin/fleet-agent`, other files in `/etc/fleet-agent`, a `state_dir` configured elsewhere) is listed and left alone. The host record on the server is not changed; retire it in the dashboard.

**Output.** Plain, ordered lines without colour. `--quiet` prints only errors and, during onboarding, one line with the page and code; `--json` prints one JSON object per line (`step`, `detail`, `warning`, `approval_required`, then `installed` or `uninstalled`, or `error` with `exit_code` and `next_step`). No output contains the credential, the token, or the device code.

| Exit | Meaning |
|---|---|
| 0 | Installed (or uninstalled, or nothing to uninstall) |
| 1 | A step on this VM failed, for example the service did not stay running; re-run after fixing the cause |
| 2 | Usage error, including a malformed token |
| 3 | Preflight failed; nothing was changed |
| 4 | Rejected: an operator rejected the request, or the server rejected the existing credential |
| 5 | Expired: the onboarding request expired, or the token is invalid, expired, or used |
| 6 | Server error or unreachable server during enrollment or the confirming heartbeat |
| 130 | Interrupted (Ctrl-C or SIGTERM) |

## Configuration

TOML, root-owned, mode `0600` ([DEC-03](../docs/decisions/0003-agent-privilege.md)). The agent refuses to start if the file is not owned by the user it runs as, is readable or writable by group or others, or contains unknown keys, so there is no way to add a setting such as `insecure`: certificate verification cannot be turned off.

```toml
server_url = "https://fleet-agent.example.lan"   # required; https only, host and optional port
credential = "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001"   # required; written by `fleet-agent install`
log_level = "info"                               # error, warn, info (default), debug, trace
# ca_file = "/etc/fleet-agent/ca.pem"            # extra CA bundle for a private CA; not needed with Let's Encrypt (DEC-05)
# state_dir = "/var/lib/fleet-agent"             # default shown; created with mode 0700

[heartbeat]                                      # optional; seconds; allowed 10..=3600
interval_seconds = 60                            # starting interval
min_seconds = 30                                 # a server-directed interval is clamped to min..=max (ADR 0019)
max_seconds = 600

[inventory]                                      # optional; seconds; allowed 60..=86400
interval_seconds = 900
min_seconds = 300
max_seconds = 21600
```

If only `interval_seconds` is set, the default bounds widen to include it.

`state_dir` is created with mode `0700` if it does not exist. An existing directory is never changed: the agent refuses to start if it is a symlink, is owned by another user, or is accessible by group or others, and says how to fix it. Never point `state_dir` at a shared directory. `ca_file` must hold only valid PEM certificates; a malformed entry is an error rather than being skipped. Config errors name the key but never repeat its value, so a misplaced credential does not end up in the logs.

## HTTP client and retries

- `rustls` with the Debian trust store (`/etc/ssl/certs/ca-certificates.crt`) plus `ca_file`. Every request sends `Authorization: Bearer <credential>` and `User-Agent: fleet-agent/<version>`. Redirects are not followed and environment proxies are ignored, so the credential only goes to `server_url`. Connect timeout 10 s, request timeout 30 s, response body at most 1 MiB.
- Errors are mapped from the envelope in [`docs/api`](../docs/api/README.md). Transient failures (unreachable, TLS, timeouts, `5xx`, other `4xx`) back off exponentially from 5 s to a cap of 5 minutes with equal jitter, and reset after a success. `401`, `403` (including `reenrollment_required`), and `426` are logged plainly and wait about 30 minutes. `429` waits at least `Retry-After`, plus up to 10% (at most a minute) so throttled agents do not retry together; only a broken header longer than a day is capped.
- Logs are `key=value` lines with an RFC 3339 UTC timestamp on stdout, for the journal. The credential is held in a type that prints `<redacted>`; logs carry its non-secret key id.

## Heartbeats and inventory reports

`run` sends heartbeats and inventory reports ([`docs/api`](../docs/api/README.md)) on two threads, so a slow collection or a hung report never delays a heartbeat. The module documentation in `src/report/` has the details.

- **Heartbeats** (FR-1.2): the first at once, then every heartbeat interval minus up to 10% jitter, so never later than the interval. Each carries the hostname, agent version, agent uptime, and agent clock. A failure waits as the retry policy says and never stops the agent; the interval resumes with the next accepted heartbeat.
- **Server-directed intervals** (ADR 0019): the heartbeat response may set `directives.intervals` (`heartbeat_seconds`, `inventory_seconds`). Each is clamped to the config's `min_seconds..=max_seconds`, logged when it changes, and dropped back to `interval_seconds` when the server stops sending it. Anything else in the response the agent does not understand, including an `agent_update` directive (acted on from P1-AGENT-UPDATE), is ignored and logged once. A clock more than 5 minutes off the server's is logged.
- **Inventory reports** (FR-1.3, DEC-07): one at startup, one every inventory interval (minus up to 10% jitter), and one within a minute of a **stable** fact changing: the facts are collected every 60 seconds and a hash of the stable ones and the agent version is compared with the last report's. Changes to free memory, free disk space, or uptime alone send nothing extra.
- **Retries:** a failed report is retried with the same `report_id` and body, so the server can discard a duplicate. Nothing is queued or replayed: a report still waiting for its retry is replaced by current state (a new `report_id`) when the stable facts change or once it is one interval old. A report rejected for its content (`400`, `413`, `422`) is logged with the server's code and message and not retried.
- **Logs:** every report line carries its `report_id`, and its outcome (`sent`, `duplicate`, or rejected with the reason). Routine accepted heartbeats are logged at `debug`.
- **State:** after each accepted report, `inventory.json` in `state_dir` records its stable hash, boot identifier, agent version, and `report_id`, written atomically. The startup report logs whether the stable facts changed and whether the host rebooted since then. A missing or corrupt record is treated as none.
- **Stopping:** `SIGTERM` or `SIGINT` ends both loops between requests; a request in flight finishes first (at most the 30 s timeout). If either loop fails unexpectedly, the agent stops and exits with status `1`, so systemd restarts it.

## Layout

| Module | Responsibility | Filled in by |
|---|---|---|
| `config` | TOML config: server URL, credential, intervals and their bounds, log level, extra CA bundle, state directory | P1-AGENT-CORE |
| `client` | HTTPS client for `/api/v1`, error mapping | P1-AGENT-CORE |
| `retry` | Backoff with jitter and cap, long waits for `401`/`403`/`426`, `Retry-After`, failure log lines | P1-AGENT-CORE |
| `shutdown` | Graceful stop on `SIGTERM` and `SIGINT` | P1-AGENT-CORE |
| `collect` | Read-only system, disk, and network collectors; see [Collected facts](#collected-facts) | P1-AGENT-COLLECT |
| `report` | Heartbeat loop, server-directed intervals, and inventory reports; see [Heartbeats and inventory reports](#heartbeats-and-inventory-reports) | P1-AGENT-REPORT |
| `state` | Persistent state in `/var/lib/fleet-agent` | P1-AGENT-CORE, P1-AGENT-REPORT |
| `fsx` | Shared file helpers: bounded reads of regular files, atomic writes, stale temporary-file cleanup | P1-AGENT-REPORT |
| `logging` | Structured journal logging, no secrets | P1-AGENT-CORE |
| `install` | `install` and `uninstall`: preflight, layout, onboarding and token enrollment, systemd unit | P1-AGENT-INSTALL |

## Collected facts

`collect::Collector` gathers the fact fields of an inventory report ([`inventory.request`](../docs/api/schemas/v1/inventory.request.schema.json)); the reporter adds the envelope. It reads files and calls syscalls directly and never runs a command. The module documentation in `src/collect/` has the full source table and rules; in short:

- **Graceful degradation.** Every field is read and parsed independently. A missing, unreadable, corrupt, or hung source makes that field `null` and adds a warning (`field`, `message`); the rest is still collected. Each read (one file or one syscall) has a 5 second limit, judged by when the read finished, so a collection ends within about 10 seconds. A read that never returns keeps its thread, but the source is not read again until it does (that field is reported as still blocked), so a stuck source holds one thread rather than one per collection. Sources must be regular files of at most 16 MiB, opened without blocking, so a FIFO or device planted at a source path is refused at once.
- **System facts** come from `/proc/sys/kernel/{hostname,osrelease}`, `/etc/os-release` (or `/usr/lib/os-release`), `uname(2)`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/uptime`, `/proc/sys/kernel/random/boot_id`, and `/etc/machine-id`. An architecture other than `x86_64` is `null` plus a warning (DEC-01).
- **Disks** are mounts from `/proc/self/mounts` whose filesystem type is not pseudo or virtual (`proc`, `sysfs`, `tmpfs`, `devtmpfs`, `cgroup2`, `overlay`, and the others listed in `src/collect/disk.rs`) and whose source is a block device under `/dev/`; network filesystems are therefore left out. A mount hidden by a later mount on the same path or on a parent directory (an overmount) is ignored, then only the first mount of each device is kept, which drops bind mounts and further btrfs subvolumes. Filesystems without a block-device source, such as ZFS datasets, are not reported. At most 128 mounts, the first by path, are passed to `statvfs`, and the first 64 are reported. Sizes come from `statvfs`: `size_bytes` and `free_bytes` are the `Size` and `Avail` columns of `df`.
- **Network interfaces** are those that are up and not loopback, minus container and VM bridges by name (`docker*`, Docker's `br-<12 hex>`, `veth*`, `virbr*`, `lxcbr*`, `lxdbr*`, `podman*`, `cni*`, `flannel*`, `cali*`, `cilium*`, `weave*`, `kube-bridge`), each with its IPv4 and IPv6 addresses in CIDR form, excluding link-local. The primary interface carries the lowest-metric IPv4 default route in `/proc/net/route`, or the IPv6 one from `/proc/net/ipv6_route` when there is no IPv4 default route. A missing IPv6 table (IPv6 disabled) is quiet; any other failure of it is a warning when it is needed. A default route on an interface that is not reported (down, a container bridge, no reportable address) is a warning, and the primary interface is kept even when the 64-interface limit is reached. A hostname or kernel version containing control characters is `null` plus a warning.
- **Partial lists.** When a list fact is readable but incomplete (one mount's `statvfs` failed, no routing table to pick the primary interface, a contract size limit reached), the entries that could be read are kept and a warning explains what is missing.
- **A report the server accepts.** Values the server would reject as a whole are fixed at the source: available memory above total memory is `null` plus a warning, and two disks or interfaces whose names match once the server strips control characters (or once invalid UTF-8 is replaced) keep only the first, with a warning. Over the contract's 64 warnings, every field with a warning keeps at least one.

Fixture tests use a fake root directory built from Debian 13 files in `tests/fixtures/collect/debian13/`. To see what the collectors report on the machine running the tests, compare the output of this ignored test with `hostnamectl`, `free -b`, `df -B1`, and `ip route`:

```sh
cargo test collects_from_this_host -- --ignored --nocapture
```

## Dependencies

The agent runs as root, so every dependency is attack surface and audit work: keep the list short, prefer pure-Rust crates, and never pull in OpenSSL or an async runtime. A dependency is added in the pull request that first uses it, not before.

| Need | Choice | Why |
|---|---|---|
| HTTP client | `ureq` with its `rustls` backend (`ring` provider), default features off | Small, blocking (the agent does one request at a time), no OpenSSL; `rustls` builds cleanly for static musl. The `rustls` feature also links Mozilla's root list (`webpki-roots`), which the agent does not use |
| TLS roots | Debian system store plus the optional CA bundle from config | Follows OS root updates; supports a private CA (FR-1.6). Verification cannot be disabled |
| Serialisation | `serde`, `serde_json` | Standard; payloads are checked against `docs/api/` schemas (P0-CONTRACT) |
| Config | `toml`, parse only | Config file format |
| Logging | `tracing`, `tracing-subscriber` (`fmt` only) | Structured fields (host, `report_id`) on timestamped lines to stdout, which systemd sends to the journal |
| Randomness | `getrandom` | Report ids and jitter seeds from the kernel (`getrandom(2)`): no file to open, so it works under systemd sandboxing, and hosts booted together do not share jitter. Already linked through `ring`, so it adds no code |
| Report ids | `uuid`, default features off | Formats the random bytes as a version 4 UUID; no dependencies of its own |
| Timestamps | `humantime` | RFC 3339 for `agent_time`, `collected_at`, and reading `server_time`; no dependencies of its own, so no date arithmetic is maintained here |
| Hashing | `ring` (SHA-256) | The stable-facts change hash. Already linked as the TLS crypto provider, so it adds no code |
| Signals | `signal-hook` | Graceful `SIGTERM`/`SIGINT` handling without an async runtime or hand-written `unsafe` |
| Syscalls | `libc` | `statvfs`, `uname`, and `getifaddrs` for the collectors, `geteuid` and `open` flags for the ownership checks, `flock` and `termios` for the installer's lock and hidden token prompt, none of which `std` exposes. No transitive dependencies; `rustix` lacks `getifaddrs` and `nix` brings more code for a few calls. The collectors' unsafe code is confined to `src/collect/sys.rs`, with a safety comment on each block |
| QR code | `qrcodegen` | The installer prints a QR code of the approval page (P1-AGENT-INSTALL). Nayuki's reference encoder: pure Rust, no dependencies, `forbid(unsafe_code)`, about 1,200 lines |

Test-only dependencies (`[dev-dependencies]`, never in the binary): `jsonschema` (default features off, so it never fetches remote schemas), which with `serde_json` checks payloads against the API contract in [`docs/api`](../docs/api/README.md) (in a test, use `assert_conforms` from `tests/support/contract.rs`); and `rcgen` plus `rustls`, which run a local TLS server with a certificate authority generated per test, so no certificate or key is checked in.

Changing a choice in this table needs a note in the pull request that does it. CI runs a dependency audit on every pull request.
