# fleet-agent

The Fleet CMDB agent: a single static Rust binary that runs as a systemd service on each VM and reports host facts to the server (FR-1.6). The fleet is Debian 13 on x86_64 ([DEC-01](../docs/decisions/0001-fleet-profile.md)), so the only release target is `x86_64-unknown-linux-musl`. The agent runs as root under a hardened unit ([DEC-03](../docs/decisions/0003-agent-privilege.md)).

Status: Phase 0 skeleton. Only `--version` and `--help` work.

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

## Layout

| Module | Responsibility | Filled in by |
|---|---|---|
| `config` | TOML config: server URL, credential, intervals, log level, extra CA bundle | P1-AGENT-CORE |
| `client` | HTTPS client for `/api/v1`, error mapping, enrollment | P1-AGENT-CORE |
| `collect` | Read-only system, disk, and network collectors | P1-AGENT-COLLECT |
| `report` | Heartbeat loop and inventory reports | P1-AGENT-REPORT |
| `state` | Persistent state in `/var/lib/fleet-agent` | P1-AGENT-CORE, P1-AGENT-REPORT |
| `logging` | Structured journal logging, no secrets | P1-AGENT-CORE |

## Dependencies

The agent runs as root, so every dependency is attack surface and audit work: keep the list short, prefer pure-Rust crates, and never pull in OpenSSL or an async runtime. A dependency is added in the pull request that first uses it, not before; this skeleton has none.

| Need | Choice | Why |
|---|---|---|
| HTTP client | `ureq` with its `rustls` backend | Small, blocking (the agent does one request at a time), no OpenSSL; `rustls` builds cleanly for static musl |
| TLS roots | Debian system store plus the optional CA bundle from config | Follows OS root updates; supports a private CA (FR-1.6). Verification cannot be disabled |
| Serialisation | `serde`, `serde_json` | Standard; payloads are checked against `docs/api/` schemas (P0-CONTRACT) |
| Config | `toml` | Config file format |
| Logging | `tracing`, `tracing-subscriber` | Structured fields (host, `report_id`) on timestamped lines to stdout, which systemd sends to the journal |

Changing a choice in this table needs a note in the pull request that does it. CI runs a dependency audit on every pull request.
