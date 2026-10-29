# fleet-agent

The Fleet CMDB agent: a single static Rust binary that runs as a systemd service on each VM and reports host facts to the server (FR-1.6). The fleet is Debian 13 on x86_64 ([DEC-01](../docs/decisions/0001-fleet-profile.md)), so the only release target is `x86_64-unknown-linux-musl`. The agent runs as root under a hardened unit ([DEC-03](../docs/decisions/0003-agent-privilege.md)).

Status: Phase 1 in progress. Config, logging, the state directory, the HTTPS client, and the retry policy are in place (P1-AGENT-CORE); `run` starts, checks everything, and waits for a stop signal. Heartbeats and inventory reports arrive with P1-AGENT-REPORT, `install` and `uninstall` with P1-AGENT-INSTALL.

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
fleet-agent --version | --help
```

The config path defaults to `/etc/fleet-agent/config.toml`. Exit status: `0` success, `2` usage error, `78` (`EX_CONFIG`) invalid, missing, or unreadable config, `1` any other startup failure. A server outage never makes the agent exit.

## Configuration

TOML, root-owned, mode `0600` ([DEC-03](../docs/decisions/0003-agent-privilege.md)). The agent refuses to start if the file is readable or writable by group or others, and rejects unknown keys, so there is no way to add a setting such as `insecure`: certificate verification cannot be turned off.

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

## HTTP client and retries

- `rustls` with the Debian trust store (`/etc/ssl/certs/ca-certificates.crt`) plus `ca_file`. Every request sends `Authorization: Bearer <credential>` and `User-Agent: fleet-agent/<version>`. Redirects are not followed and environment proxies are ignored, so the credential only goes to `server_url`. Connect timeout 10 s, request timeout 30 s, response body at most 1 MiB.
- Errors are mapped from the envelope in [`docs/api`](../docs/api/README.md). Transient failures (unreachable, TLS, timeouts, `5xx`, other `4xx`) back off exponentially from 5 s to a cap of 5 minutes with equal jitter, and reset after a success. `401`, `403` (including `reenrollment_required`), and `426` are logged plainly and wait about 30 minutes. `429` waits at least `Retry-After` (at most an hour).
- Logs are `key=value` lines with an RFC 3339 UTC timestamp on stdout, for the journal. The credential is held in a type that prints `<redacted>`; logs carry its non-secret key id.

## Layout

| Module | Responsibility | Filled in by |
|---|---|---|
| `config` | TOML config: server URL, credential, intervals and their bounds, log level, extra CA bundle, state directory | P1-AGENT-CORE |
| `client` | HTTPS client for `/api/v1`, error mapping | P1-AGENT-CORE |
| `retry` | Backoff with jitter and cap, long waits for `401`/`403`/`426`, `Retry-After`, failure log lines | P1-AGENT-CORE |
| `shutdown` | Graceful stop on `SIGTERM` and `SIGINT` | P1-AGENT-CORE |
| `collect` | Read-only system, disk, and network collectors | P1-AGENT-COLLECT |
| `report` | Heartbeat loop and inventory reports | P1-AGENT-REPORT |
| `state` | Persistent state in `/var/lib/fleet-agent` | P1-AGENT-CORE, P1-AGENT-REPORT |
| `logging` | Structured journal logging, no secrets | P1-AGENT-CORE |

## Dependencies

The agent runs as root, so every dependency is attack surface and audit work: keep the list short, prefer pure-Rust crates, and never pull in OpenSSL or an async runtime. A dependency is added in the pull request that first uses it, not before.

| Need | Choice | Why |
|---|---|---|
| HTTP client | `ureq` with its `rustls` backend (`ring` provider), default features off | Small, blocking (the agent does one request at a time), no OpenSSL; `rustls` builds cleanly for static musl. The `rustls` feature also links Mozilla's root list (`webpki-roots`), which the agent does not use |
| TLS roots | Debian system store plus the optional CA bundle from config | Follows OS root updates; supports a private CA (FR-1.6). Verification cannot be disabled |
| Serialisation | `serde`, `serde_json` | Standard; payloads are checked against `docs/api/` schemas (P0-CONTRACT) |
| Config | `toml`, parse only | Config file format |
| Logging | `tracing`, `tracing-subscriber` (`fmt` only) | Structured fields (host, `report_id`) on timestamped lines to stdout, which systemd sends to the journal |
| Signals | `signal-hook` | Graceful `SIGTERM`/`SIGINT` handling without an async runtime or hand-written `unsafe` |

Test-only dependencies (`[dev-dependencies]`, never in the binary): `jsonschema` (default features off, so it never fetches remote schemas), which with `serde_json` checks payloads against the API contract in [`docs/api`](../docs/api/README.md) (in a test, use `assert_conforms` from `tests/support/contract.rs`); and `rcgen` plus `rustls`, which run a local TLS server with a certificate authority generated per test, so no certificate or key is checked in.

Changing a choice in this table needs a note in the pull request that does it. CI runs a dependency audit on every pull request.
