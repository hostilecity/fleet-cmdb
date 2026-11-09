# P3-TASK-MODEL: Task catalog, task and batch models, state machine

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-S01: Task catalog: shared definition, server mirror, and parameter validation

### Scope

- One catalog definition file (for example `docs/api/task-catalog.yml`) that both server and agent consume. Per entry: stable type id, plain-language name, an exact description of what it runs, a closed parameter schema, default timeout, default expiry, whether it is interruptible, the privilege it needs, and the minimum catalog version.
- Initial entries: `refresh_reports` (re-collect inventory, config, packages; reuses the [DEC-13](../../decisions/0013-on-demand-reports.md) mechanism), `restart_service`, and `apply_package_updates` (parameters per [DEC-16](../../decisions/0016-package-update-policy.md)).
- Parameter schemas are closed: `additionalProperties: false`; every string parameter has an enum or a strict pattern and a maximum length. **A catalog lint rejects** any parameter whose name or shape suggests a command (`command`, `cmd`, `shell`, `script`, `args`, `exec`, `path`, free-form strings).
- Server loads the catalog at boot and validates parameters at task creation ([P3-S02](p3-task-model.md)) and again at claim time.
- The agent embeds the same file at compile time (see [P3-A01](p3-agent-ledger.md)); a contract test fails if the two sides disagree.
- Adding a task type requires a catalog change, a new agent release, and a server release. A documented procedure and a checklist in the PR template.

### Acceptance criteria

- [ ] The catalog lint rejects a schema with a free-form string parameter, a `command` field, or `additionalProperties: true`
- [ ] Parameter validation rejects extra fields, wrong types, oversize values, and out-of-enum values
- [ ] There is no code path that builds a catalog entry from request input
- [ ] The server and agent catalogs are verified identical in CI

## P3-S02: Task and batch models, state machine, bulk creation, expiry

### Scope

- `task_batches` (operator, type, validated parameters, selection method, created) and `tasks` (batch, host, type, parameters, state, expires at, lease expiry, claimed, started, finished, exit status, reason, output and truncation marker, cancel requested, agent-reported times kept separately).
- States: `queued`, `claimed`, `running`, `succeeded`, `failed`, `timed_out`, `cancelled`, `refused`, `expired`. Explicit transition table; terminal states immutable. Reasons for `failed` and `refused` are enumerated codes (`interrupted`, `lease_expired`, `invalid_params`, `unknown_type`, `not_enabled_locally`, `not_allowed_locally`, and so on).
- Bulk creation by tag or explicit selection creates one independent task per host in a single transaction; the target set is resolved and recorded at creation. Only `active` hosts that advertise support for the type ([P3-A01](p3-agent-ledger.md)) are targeted; excluded hosts are listed with reasons.
- Batch size cap and expiry defaults per [DEC-14](../../decisions/0014-task-trust-model.md).
- Parameters are validated against the catalog ([P3-S01](p3-task-model.md)); there is no parameter or attribute that can carry a command.

### Acceptance criteria

- [ ] A bulk request for N hosts creates N independent tasks; one failing does not affect others
- [ ] Every legal transition has a spec; illegal ones raise
- [ ] A request containing any command-like field is rejected without creating records
- [ ] Hosts that are not active or do not support the type are excluded and reported

## As built

### P3-S01

- **The file is `docs/api/tasks/task-catalog.json`**, with its schema `task-catalog.schema.json` and lint examples beside it; [`docs/api/tasks/README.md`](../../api/tasks/README.md) describes the format, the lint, and the procedure for adding a type. It is JSON, not YAML, so the agent compiles it in with `serde_json`, which it already has, and carries no YAML parser. The format is fixed from the first commit on the branch, because the agent work (P3-A01, #34) builds on it.
- **Fields per entry:** `type`, `name`, `description`, `since` (the catalog version that added the type: the "minimum catalog version"), `privilege` (`read_only`, `service_manager`, or `package_manager`), `interruptible`, `enabled_by_default` (DEC-14: only `read_only` types may be), `timeout_seconds`, `expiry_seconds`, and `parameters`, a closed JSON Schema. `catalog_version` and `format_version` at the top.
- **Initial entries:** `refresh_reports` (no parameters: it always collects all three reports, as the dashboard's "Request fresh reports" does), `restart_service` (one parameter, `service`: a full systemd service unit name ending in `.service`, at most 256 characters, from letters, digits, and `_ . @ -`, starting with a letter or digit), and `apply_package_updates` (no parameters, 60-minute timeout, not interruptible; DEC-16). Every type expires after 24 hours (DEC-14).
- **The lint** (`TaskCatalog.lint` in `cmdb/lib/task_catalog.rb`, plus the schema) also refuses lists and objects as parameters, defaults, `patternProperties`, unbounded integers, loose patterns (a `.` wildcard, a negated class, a special group, any escape but `\. \- \+ \d`, or any character outside letters, digits, and `_ . @ + -`), command-like names (also `argv`, `option`, `flag`, `env`, `file`, `dir`, `url`, `uri`, `program`, `binary`, `sudo`, `eval`), duplicate JSON keys, and files that are not UTF-8. The command-like-name, closed-schema, and free-form checks are in the Ruby code as well as the schema, so loosening the schema alone does not loosen the lint. The server loads and lints the file at boot (`config/initializers/task_catalog.rb`); the Docker image copies it in from the `api` build context (`FLEET_TASK_CATALOG_DIR`).
- **Parameter validation** (`TaskCatalog::Entry#parameter_errors`) is hand-written for the three parameter types rather than delegated to a JSON Schema library, so it is short enough to review: extra fields, missing required ones, wrong types (a number with a fraction is not an integer), oversize values (and parameters over 4 KiB as JSON), and values outside an enum or pattern are refused; messages never repeat the value. Patterns are matched with `\A` and `\z`, so a value cannot end in a newline. Creation uses it through `TaskPolicy.refusal`; claim-time revalidation (P3-S03, #30) calls `Task#refusal_reason`, which runs the same checks against the current catalog and policy.
- **Server and agent catalogs identical in CI:** the server half is done: the contract spec checks that the server reads `docs/api/tasks/task-catalog.json`, that its digest is the file's SHA-256, and that no other copy of the catalog exists in the repository. The agent half, a test that the bytes the agent compiles in are that file, comes with the agent's embedding (P3-A01, #34).
- **Adding a task type:** the procedure is in `docs/api/tasks/README.md`, and the pull request template has a checklist item for it.

### P3-S02

- **Tables:** `task_batches` (operator, type, validated parameters, `selection_method` `explicit` or `tag`, the tag, `selected_host_ids` as resolved, `excluded_hosts` with reasons, the typed `confirmed_host_count`, the catalog version and digest, created) and `tasks` (a `uuid` for the agent, batch, host, type, parameters, state, reason, timeout, expires at, lease expiry, claimed, started, finished, exit status, output and `output_truncated`, cancel requested at and by, and the agent-reported start and finish kept separately). Output is capped at 1 MiB in the database whatever the configured limit (P3-S04).
- **States and transitions** are `Task::TRANSITIONS`: `claim` (queued to claimed), `requeue` (claimed to queued, when a lease lapses before the agent started), `start` (claimed to running), `succeed` (running), `fail` (claimed or running: claimed covers an agent that recorded the task as started but crashed before acknowledging it, and reports `interrupted`), `time_out` (running), `cancel` (queued, claimed, or running when the type is interruptible), `refuse` (queued, claimed, or running: nothing was run), and `expire` (queued). Every other pair raises `Task::InvalidTransition`; each transition writes one audit entry with the actor it is given (operator, host, or system). Terminal states are read-only.
- **Reasons:** failed `nonzero_exit`, `interrupted`, `lease_expired`, `lock_timeout`, `agent_error`; refused `unknown_type`, `invalid_params`, `not_supported`, `not_enabled_locally`, `not_allowed_locally`, `not_allowed_on_server`, `protected_service`. The result API (P3-S04) publishes the agent's subset in its schema.
- **Database guards:** `tasks_guard` enforces the same transition table, that a task starts queued, that terminal tasks never change, and that a task's batch, host, type, parameters, expiry, and timeout never change; `task_batches_guard` makes batches immutable. Neither table allows `DELETE` or `TRUNCATE`.
- **Bulk creation** is `TaskBatches.create!(request, operator:)`. The request is a closed object (`type`, `parameters`, `target` with `host_ids` or `tag`, `confirm_host_count`); any other key, at any level, refuses it with nothing written. Exclusion reasons: `not_active`, `machine_id_mismatch` (FR-S.1), `no_capability_report`, `not_supported` (the agent's catalog is older than the type's `since`, or the agent does not implement it), and `not_enabled`.
- **Capabilities:** `hosts` gains `task_catalog_version`, `task_types_supported`, `task_types_enabled`, and `task_capabilities_reported_at`. Nothing writes them yet: the agent reports them in P3-A01 (#34), and the endpoint field that records them comes with it. Until then every host is excluded with `no_capability_report`, so no task can be created.
- **Server restart allowlist and protected services:** `TaskPolicy` refuses protected services (DEC-15: the agent's own unit, `ssh` and `sshd`, `systemd-*`, networking, `NetworkManager`, `ifup@*`, `dbus`, `dbus-broker`) and anything not on the server's restart allowlist. The allowlist's setting and page are P3-S06 (#31); until then it is empty, as DEC-15 sets by default, so a restart task cannot be created.
- **Batch limits:** a selection of more than 25 hosts is refused before exclusions are counted, so a wide tag cannot be narrowed into a batch by accident; above 3 targeted hosts `confirm_host_count` must equal the number of tasks (DEC-14), enforced in the service so a forged dashboard POST is held to it too (P3-S08). A request that leaves no host to target creates nothing.
- **Audit:** `task.batch_created`, `task.created` (per task), and one entry per transition: `task.claimed`, `task.requeued`, `task.started`, `task.succeeded`, `task.failed`, `task.timed_out`, `task.cancelled`, `task.refused`, `task.expired`. Output is never in an entry. The cancel-requested entry for a running, non-interruptible task, and the completeness checklist, are P3-S07 (#31).
- **Not here:** endpoints (P3-S03, P3-S04), lease, expiry, and timeout jobs and cancel-requested handling (P3-S05), settings for limits and per-type expiry (P3-S06), and the dashboard (P3-S08 to P3-S10).
