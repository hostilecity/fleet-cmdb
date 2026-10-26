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
