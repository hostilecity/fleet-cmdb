# P3-AGENT-LEDGER: Agent task config, capabilities, poller, and durable ledger

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-A01: Agent: local task configuration, embedded catalog, and capability reporting

### Scope

- `[tasks]` section in the agent config: enabled task types (default: none or only `refresh_reports`, per [DEC-14](../../decisions/0014-task-trust-model.md)), allowed services, limits. Invalid configuration fails safe (nothing enabled).
- The task catalog is compiled into the binary from the shared catalog file ([P3-S01](p3-task-model.md)); the agent never loads task definitions at runtime from the server.
- Reports supported task types, enabled task types, and catalog version to the server (heartbeat or inventory), so the server only offers what the host will run.
- Config validation message when a listed type or service is unknown.

### Acceptance criteria

- [ ] With default configuration, `apply_package_updates` and `restart_service` are not enabled
- [ ] The catalog compiled into the binary matches the shared file (build-time check)
- [ ] The server sees the capability report and stops offering disabled types

### As built

- **Catalog.** The shared file is `docs/api/tasks/task-catalog.json` (JSON, not YAML, so the agent reads it with `serde_json` and has no YAML parser; [P3-S01](p3-task-model.md)). The agent compiles in that file itself with `include_str!` (`agent/src/tasks/catalog.rs`), with no copy to drift. A unit test compares the compiled-in bytes with the file, `agent/tests/contract.rs` checks that the `include_str!` path is the shared file and that the file passes its schema, and the server's contract spec checks that no other copy exists. Building the agent therefore needs the repository, not just `agent/`, and the Docker command in `agent/README.md` mounts the root. The agent parses the catalog on first use, reads every field and refuses unknown ones, and checks what it relies on: format 1, unique type ids, `since` within the catalog version, only `read_only` types on by default, and closed parameter schemas. A catalog that failed these checks would leave the agent supporting nothing; the unit tests parse it, so that fails CI first.
- **Config.** `[tasks]` in the agent config, with `enabled` (task type ids; absent means the catalog's `enabled_by_default` types, which is `refresh_reports` alone, and only a `read_only` type can be on by default) and `allowed_services` (full service unit names matching the catalog's `service` pattern, at most 64, empty by default). Protected units (DEC-15) are refused even when listed: the agent's own units (`fleet-agent*`), `ssh`/`sshd`, `systemd`/`systemd-*`, `networking` and `NetworkManager`, `dbus` and `dbus-broker`, template instances included. `apply_package_updates` has no local setting (DEC-16 fixes its policy). There are no other limits in this section: the poll interval belongs to P3-A02 and timeouts come from the catalog and the server (P3-A03). Code: `agent/src/tasks/settings.rs`.
- **Fails safe.** The section is validated as strictly as the rest of `config.rs` (unknown keys, wrong types, unknown types, malformed, protected, or repeated services), but an error turns every task off instead of stopping the agent: heartbeats and reports carry on, the error is logged at startup, the capability report says `local_config: invalid`, and `fleet-agent check-config` fails with exit 78 and the message. Messages name an unknown type and list the catalog's, and never repeat a configured service name. `fleet-agent install` keeps the section when it rewrites the config; one that was invalid is written as `enabled = []` with the old error in a comment, so a reinstall never turns a task on.
- **Capabilities.** Every heartbeat (including the installer's first) carries `tasks`: `catalog_version`, `supported` (the types this agent version implements: none until P3-A03 onwards fill `tasks::IMPLEMENTED`), `enabled`, and `local_config`. The heartbeat was chosen over inventory so a change shows within a minute of the agent restarting. Schema and examples in `docs/api` (`heartbeat.request`); the heartbeat body limit rose to 16 KiB for the largest lists the schema allows. The local service allowlist is not reported: the agent refuses a restart outside it (AC-3.9), and the server's own allowlist is P3-S05's.
- **Server.** The heartbeat writes the report to the host columns P3-S02 added (`task_catalog_version`, `task_types_supported`, `task_types_enabled`, `task_capabilities_reported_at`), in the heartbeat's one UPDATE (`Liveness.record_heartbeat!`). `local_config: invalid` stores no enabled types. A heartbeat without `tasks` clears the columns, so the host is excluded with `no_capability_report`. `Host#task_exclusion_reason` (P3-S02) reads them when a batch is created, which is how the server stops offering disabled types. `local_config` itself is not stored yet; a dashboard view (P3-D*) can add it.
- **Not in this part:** the poller and ledger (P3-A02), and showing capabilities, including `local_config`, on the dashboard (P3-D*).

## P3-A02: Agent: task poller and durable local task ledger

### Scope

- Poll at a configurable interval (default 30 seconds) and promptly when the heartbeat directive says tasks are available; at most one task in flight; backoff on failures as in [P1-A02](p1-agent-core.md).
- A durable ledger in the state directory (append-only records, `fsync`ed) with these steps per task id: `received`, `started`, `finished`, `reported`.
- **The `started` record is written and flushed before anything is executed.** Only then is the server acknowledged ([P3-S03](p3-task-api.md)) and the task run.
- A task id already present in the ledger is never run again. At startup the agent reconciles: `started` without `finished` is reported as `failed` with reason `interrupted`; `finished` without `reported` is re-reported; unknown states are reported, not executed.
- Ledger growth is bounded (compaction of old reported tasks).
- Result reporting retries until accepted, idempotently.
- An agent update ([P1-AGENT-UPDATE](p1-agent-update.md)) is deferred while a task is in flight, and an update in progress blocks new claims until it is confirmed or rolled back.

### Acceptance criteria

- [ ] Duplicate delivery of the same task id results in one execution
- [ ] Killing the agent after the `started` record is written and restarting reports `interrupted` and does not re-run the task
- [ ] A corrupted or truncated ledger tail is handled without running anything that may have run before
