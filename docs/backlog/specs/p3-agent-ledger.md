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
