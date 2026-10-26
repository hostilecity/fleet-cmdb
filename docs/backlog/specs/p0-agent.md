# P0-AGENT: Bootstrap the Rust agent crate and its CI

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## SETUP-03: Bootstrap the Rust agent crate in agent/

### Scope

- `cargo init` an `agent/` binary crate (name `fleet-agent`), pinned toolchain via `rust-toolchain.toml`.
- Module skeleton: `config`, `client`, `collect`, `report`, `state`, `logging` (empty modules with doc comments describing each responsibility).
- Dependency choices recorded in the crate README: HTTP client with `rustls` (no OpenSSL), serde and `serde_json`, a TOML config parser, structured logging. Keep the dependency list short; the agent runs as a privileged service.
- `--version` prints the agent version and agent schema version.
- Cross-compilation to the static `musl` targets listed in [DEC-01](../../decisions/0001-fleet-profile.md) verified locally.

### Acceptance criteria

- [ ] `cargo build --release --target <musl target>` produces a statically linked binary (verified with `file` or `ldd`)
- [ ] `fleet-agent --version` works
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test` pass

## SETUP-05: CI for the Rust agent (fmt, clippy, tests, audit, musl build)

### Scope

- GitHub Actions workflow: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, dependency audit (`cargo audit` or `cargo deny`), and a release build for each musl target in [DEC-01](../../decisions/0001-fleet-profile.md).
- Cache the cargo registry and target directory.
- Path filtering as in [SETUP-04](p0-server-ci.md).
- Dependabot for cargo.
- Release publishing is **not** in this issue; it is part of [P1-A08](p1-packaging.md).

### Acceptance criteria

- [ ] A PR touching `agent/` runs the workflow and reports status
- [ ] Build artefacts for each target are produced on `main` (uploaded as workflow artefacts)
