# Agent API contract

This directory is the single source of truth for the agent API (FR-S.2, NFR-5). The server validates requests against these schemas, and both test suites read the schemas and examples from here rather than keeping copies:

- `cmdb/spec/contract/api_contract_spec.rb`, with `cmdb/spec/support/api_contract.rb`
- `agent/tests/contract.rs`, with `agent/tests/support/contract.rs`

The conventions below are decided in [DEC-08](../decisions/0008-api-conventions.md).

## Layout

```
docs/api/
  schemas/v1/<name>.schema.json           one JSON Schema (draft 2020-12) per request and response
  examples/v1/<name>/valid/*.json         payloads that must validate
  examples/v1/<name>/invalid/*.json       payloads that must be rejected; the file name says why
  rules/                                  the CIS-aligned rule file format (not part of the agent API; see rules/README.md)
  tasks/                                  the task catalog the server and the agent both build from (see tasks/README.md)
```

`<name>` is `<endpoint>.request` or `<endpoint>.response`. The directory version is the payload `schema_version`: everything under `v1/` is schema version 1.

## Endpoints

All endpoints are under `/api/v1`, served only on the private agent hostname ([DEC-05](../decisions/0005-hosting-tls-deployment.md)), and speak JSON over HTTPS.

| Endpoint | Auth | Request | Success |
|---|---|---|---|
| `POST /api/v1/enroll` | Enrollment token in the body | `enroll.request` | `201`, `enroll.response` |
| `POST /api/v1/onboarding` | None (agent hostname only, rate-limited and capped) | `onboarding.request` | `201`, `onboarding.response` |
| `POST /api/v1/onboarding/token` | Device code in the body | `onboarding-token.request` | `202` (pending) or `201` (approved, with the credential), `onboarding-token.response` |
| `POST /api/v1/heartbeat` | Bearer credential | `heartbeat.request` | `200`, `heartbeat.response` |
| `POST /api/v1/reports/inventory` | Bearer credential | `inventory.request` | `200`, `inventory.response` |
| `POST /api/v1/reports/packages` | Bearer credential | `packages.request`, optionally gzip | `200`, `packages.response` |
| `POST /api/v1/reports/config` | Bearer credential | `config.request`, optionally gzip | `200`, `config.response` |
| `GET /api/v1/manifest/config` | Bearer credential | none | `200`, `config-manifest.response`, or `304` |
| `POST /api/v1/update-results` | Bearer credential | `update-result.request` | `200`, `update-result.response` |
| `GET /api/v1/releases/<version>/manifest`, `.../signature`, `.../binary` | None (agent hostname only, rate-limited per address) | none | `200` (or `206`, `304`, `416`), the release file's bytes |
| `POST /api/v1/tasks/poll` | Bearer credential | `task-poll.request` | `200`, `task-poll.response` |
| `POST /api/v1/tasks/<id>/start` | Bearer credential | `task-start.request` | `200`, `task-start.response` |
| `POST /api/v1/tasks/<id>/progress` | Bearer credential | `task-progress.request` | `200`, `task-progress.response` |
| `POST /api/v1/tasks/<id>/result` | Bearer credential | `task-result.request` | `200`, `task-result.response` |

### Updates

The scope change in #54 ([DEC-17](../decisions/0017-agent-onboarding.md), [DEC-18](../decisions/0018-signed-agent-updates.md)) adds two pieces to the contract, built by P1-UPDATES:

- **The `agent_update` directive** in `heartbeat.response` (below): the rollout, the version, and the three URLs to fetch it from.
- **`POST /api/v1/update-results`:** the agent reports `succeeded`, `failed`, or `rolled_back` (with a `reason`) for a rollout, with a `report_id` reused on retry; a retried result is answered `200` with `duplicate: true`. `400 validation_failed` also covers a `rollout_id` the host is not part of and a `version` that is not the rollout's release (the `details` pointer names the field). A `failed` or `rolled_back` result halts the rollout.

**The update path never sees `426`** (FR-S.5, DEC-18). Heartbeats, update results, and release downloads are exempt from the minimum agent version, so an agent that is too old for everything else can still heartbeat, receive the directive, download the release, and report the outcome. Every other endpoint, reports included, still answers `426 agent_version_unsupported` to it; the agent does not read directives from a `426`, so the server sends none there. The test `spec/requests/api/update_path_spec.rb` (P1-X01) guards this and is kept in every later phase.

### Tasks

Remote tasks (FR-3.2, P3-S03, P3-S04; [DEC-14](../decisions/0014-task-trust-model.md)). The server never sends a command: a task is a [catalog](tasks/README.md) type id and parameters valid against that type's closed schema, and the agent checks both again against its own embedded catalog and its local configuration before it runs anything. `<id>` is the task's `id` from the poll, a UUID.

- **Poll** (`POST /api/v1/tasks/poll`): returns `{"task": null}` or one task with `id`, `type`, `parameters`, `timeout_seconds` (the deadline, relative to the start), and `catalog_version`. Nothing else. A host has at most one task claimed or running at a time:
  - A queued task is claimed for the host in one atomic step, oldest first, and only while its `expires_at` is later than the database's clock at that moment, so an expired task is never delivered (AC-3.8). The claim holds a lease (5 minutes until the agent starts the task); when it lapses, the task goes back to the queue.
  - Claiming re-validates the type and parameters against the current catalog and the server's policy (protected services, the server's restart allowlist entries for this host's tags). A task that no longer passes becomes `refused` with its reason, is never delivered, and the poll moves on to the next.
  - While the host holds a claimed task it has not started, every poll returns that same task again (for example after the agent restarts), so **the agent checks its ledger before running anything** and never runs an id twice (P3-A02). A claimed task is not returned after its `expires_at`: it expires, and the poll moves on.
  - While a task is `running`, the poll returns `null`: a task the server knows has started is never delivered again.
  - `poll_seconds` is the poll interval the server wants (Settings: Tasks, default 30, 10 to 300). The agent clamps it to its own bounds.
  - `cancel` (`{"id": ...}`) asks the agent to stop its running task: sent while an operator has asked to cancel a running task of an interruptible type, until its result arrives. The agent stops it and reports `cancelled`, or reports the real outcome if it had already ended. A task of a type that cannot be interrupted is never named: it runs to completion (DEC-14).
- **Start** (`POST /api/v1/tasks/<id>/start`, with `started_at` from the agent's clock): sent after the agent has written and flushed its `started` ledger record. A claimed task becomes `running`; a running one stays so (repeating the request is safe). The response's `run` is `true` only then. **The agent runs the task only after `run: true`**; for any other state (for example `cancelled` or `refused`) it records that it did not run the task and drops it. A start that arrives after the claim lapsed answers `state: queued`, `run: false`; the next poll delivers the same id again (P3-S05, threat model L2).
- **Leases and expiry** (P3-S05): a running task with no result by its deadline plus 5 minutes is ended by the server, as `timed_out` if the agent was heard from after the deadline, or `failed` with `lease_expired` if it was not. A result sent afterwards is kept as a late result.
- **Progress** (`POST /api/v1/tasks/<id>/progress`, optional `percent`): recorded while the task is running and ignored otherwise; the response's `state` tells the agent if the server has already ended the task, and `cancel` (as in the poll) asks it to stop.
- **Result** (`POST /api/v1/tasks/<id>/result`): `outcome` (`succeeded`, `failed`, `timed_out`, `cancelled`, `refused`), `reason` (required for `failed` and `refused`, from the agent's codes in the schema; null otherwise), `exit_status`, `started_at` and `finished_at` from the agent's clock (stored apart from the server's own times), `details` (`reboot_required`, `services_needing_restart`, `unit_active`, `reports_sent`), `output`, and `output_truncated`, with a `report_id` reused on retry.
  - `failed` and `refused` are accepted for a claimed or running task (an agent that finds a started task with no result when it starts again reports `failed`/`interrupted`); `succeeded` and `timed_out` only for a running one; `cancelled` only for a running task of an interruptible type.
  - **Output** is stored as inert text: invalid UTF-8 is replaced, terminal escape sequences and control characters other than tab and newline are removed, and output over the server's limit (Settings: Tasks, 64 KiB by default, 4 KiB to 1 MiB) keeps its start and end with a marker line where the middle was cut, and `output_truncated` set. The agent sends at most 131072 characters.
  - **Idempotent:** the same result again is answered `200` with `duplicate: true` and changes nothing. A different result for a task that already has one is `409 task_conflict`, logged and audited, and the agent stops retrying it.
  - **Late results:** when the server has already ended the task itself (`timed_out`, `expired`, `failed` with `lease_expired`, `cancelled`, or `refused` at claim), the result is kept as an annotation beside the task (`applied: false`) and the state does not change. Terminal states never change.
  - A result for a task in a state it cannot end from (for example `succeeded` for a task that was never started) is `409 task_conflict`, and the agent stops retrying it.
- **Another host's task** is `404 not_found` on every endpoint, exactly like an id that does not exist (FR-S.2). Every task endpoint needs an active host and enforces the minimum agent version.
- **The `tasks_available` heartbeat directive** (`{}`) is sent while the host has a queued, unexpired task or a claimed one it has not started, and nothing running, so the agent polls at once instead of waiting for its poll interval.

### Release downloads

The files of a signed release the server has imported ([docs/releases.md](../releases.md), P1-RELEASES): the manifest (`application/json`), its minisign signature (`text/plain`), and the static binary (`application/octet-stream`), byte for byte as published. They are not JSON API responses and have no schema; agents verify them against the release keys built into them, never trusting the server's checks (ADR 0018).

- **No credential:** releases are public, and the installer has none yet. Limited per client address instead (`429 rate_limited` with `Retry-After`).
- **No minimum version:** these paths never answer `426`, so an agent too old for the rest of the API can still fetch the release that updates it (FR-S.5).
- **Caching and resuming:** each response has a strong `ETag` (the SHA-256 of the file, quoted; for the binary, the manifest's `sha256`), `Content-Length`, and `Content-Disposition` with the release workflow's file name. `If-None-Match` gives `304`. The binary also has `Accept-Ranges: bytes` and serves one byte range (`206` with `Content-Range`; `416` past the end), honouring `If-Range`; several ranges get the whole file. A release never changes once imported.
- **Errors:** an unknown version is `404 not_found`. URLs are location-independent: the update directive (P1-UPDATES) will carry them, so they may later point elsewhere, such as a CDN, without an agent change (ADR 0019).

## Conventions

- **Authentication:** `Authorization: Bearer <key_id>.<secret>`. The host is always the one the credential belongs to. No request body names a host.
- **Versions:** every request body carries `agent_version` (semantic version) and `schema_version` (integer). Agents also send `User-Agent: fleet-agent/<agent_version>`.
- **Validation:**
  - Unknown fields are ignored and logged, so schemas do not set `additionalProperties: false`.
  - Wrong types, out-of-range values, and unknown values of enumerated fields are rejected.
  - Formats such as timestamps, UUIDs and credentials are checked with `pattern`, not `format`, so every validator agrees. Patterns cannot express every calendar rule (for example 30 February), so the server also parses timestamps and addresses when it implements an endpoint.
- **Identifiers:**
  - Every report carries a `report_id`: a UUIDv4, generated per report and reused on retry.
  - A report whose `report_id` was already processed is answered `200` with `duplicate: true` and changes nothing.
- **Timestamps:** RFC 3339 in UTC with a `Z` suffix, for example `2026-01-01T12:00:00Z`.
- **Missing facts:** a fact the agent cannot read is sent as `null`, with an entry in `warnings`. The report is still sent (FR-1.3). A list fact (`disks`, `network_interfaces`) that could be read only in part keeps the entries that were read, with a `warnings` entry saying what is missing (P1-AGENT-COLLECT).
- **Server checks beyond the schema:** some rules are not expressible in JSON Schema, such as free space not exceeding total. The server enforces these and answers `validation_failed`.
- **Heartbeat directives** ([DEC-20](../decisions/0020-named-heartbeat-directives.md)): `directives` in `heartbeat.response` is an object keyed by directive name, and `{}` when the server has nothing to say. Every directive is optional, and each is an object or `null`. An absent or `null` directive or field means no instruction. Agents ignore and log names and fields they do not know, so adding a directive, or an optional field to one, is additive (rule 1 below); changing what one means is breaking (rule 2). A malformed directive is ignored and logged, and never fails the heartbeat. Defined in v1:
  - `intervals`: `heartbeat_seconds` and `inventory_seconds`, whole seconds of at least 1, each optional. The agent clamps each to its configured bounds and returns to its configured value when one is absent (ADR 0019).
  - `agent_update`: the release to install (ADR 0018). `rollout_id`, `version`, `manifest_url`, `signature_url`, and `binary_url` (all required when the directive is an object; the URLs are `https`). Sent only to a host chosen for an open stage of the running rollout that runs an older version than the release, and on every heartbeat until it reports a result. The URLs only say where to fetch; the agent verifies the release itself (ADR 0018) and the server never names a command or an executable. The server sends `intervals` only when an operator has set them (settings `agent.heartbeat_seconds` and `agent.inventory_seconds`).
  - `report_request`: `types`, the report types an operator asked for, at least one and each once: `config`, `inventory`, or `packages` (required when the directive is an object; [DEC-13](../decisions/0013-on-demand-reports.md), P2-S03). Sent on every heartbeat until a report of each type is accepted whose `collected_at` is later than the `agent_time` of the first heartbeat that carried the request (both the agent's clock), or the request expires after an hour. The agent sends one report of each type, collected after it received the directive, through that type's endpoint as soon as it can. An agent that ignores the directive is unaffected: its next scheduled report of a type satisfies the request. Agents ignore a type they do not know, so a new type is additive.
  - `tasks_available`: `{}`, no fields. The host has a task waiting: poll `POST /api/v1/tasks/poll` now (P3-S03; see [Tasks](#tasks)). It carries no task itself, and an agent that ignores it gets the task at its next scheduled poll.
- **Task capabilities** (FR-3.1, P3-A01): `heartbeat.request` carries an optional `tasks` object on every heartbeat: the `catalog_version` of the [task catalog](tasks/README.md) compiled into the agent, the catalog types it can run (`supported`), the types its VM's local configuration enables (`enabled`; only `refresh_reports` by default, DEC-14), the services that configuration allows `restart_service` to restart (`allowed_services`, DEC-15), and `local_config` (`valid`, or `invalid` when the agent refused its `[tasks]` section and enabled nothing). Type ids are checked by pattern, not an enum, so a newer agent's types do not fail the heartbeat; the server ignores types its catalog lacks. The server stores the latest lists and version on the host, replacing them on every heartbeat (a heartbeat without the object clears them, and `invalid` stores no enabled types), and creates a task only for an active host that reports the type both supported and enabled, and, for a restart, the service in `allowed_services` (`Host#task_exclusion_reason`, P3-S02; owner, P3-D01 Q7). The agent still refuses anything it has not enabled, whatever the server sends. The heartbeat body limit is 32 KiB, for the largest lists the schema allows.
- **Compression:** `POST /api/v1/reports/packages` and `POST /api/v1/reports/config` also take a body sent with `Content-Encoding: gzip`. Their 4 MiB limit applies to the body as JSON, sent plain or once decompressed; a compressed body may be at most 1 MiB on the wire, like every other request. Every other endpoint, and any other encoding, answers `400 validation_failed`.
- **Package reports** (FR-2.3): `manager` is `dpkg`; `unsupported` (no dpkg, or another manager) with an `unsupported_reason` and no packages; or `unreadable` (dpkg is there but its packages could not be listed) with the reason in the same field and no packages. So a host whose packages cannot be listed is never shown as having none, and the server keeps what it knew before an `unreadable` report. The optional `skipped` array (at most 64 `{name, reason}`; `name` as a package name, `reason` 1 to 128 characters, no architecture) names packages the agent could read but did not list as installed, such as an interrupted installation (`unpacked`, `half-installed`, `half-configured`; the trigger states `triggers-awaited` and `triggers-pending` are installed and listed in `packages`); it must be empty or absent when `manager` is not `dpkg`. The server shows a skipped package that was installed before as skipped, not removed. `warnings` stays for everything else. Each package has its `name`, `version` exactly as dpkg records it (with any epoch; any printable ASCII without spaces, so a version dpkg only warns about is still reported), `architecture`, and `source` package (`null` when dpkg records none). A name and architecture appear at most once (`400 validation_failed` with the pointer otherwise). Versions are compared with dpkg's rules, never as strings (FR-2.4).
- **Config fact manifest** (FR-2.1): the versioned list of facts an agent may report, with each fact's key, type, `since` version, and limits. It names fact keys only, never commands. It carries no agent version, so it is exempt from `426`, and it is sent with a strong `ETag` (`If-None-Match` gives `304`). How to add a fact: [config-facts.md](../operations/config-facts.md).
- **Config reports** (FR-2.1, P2-S02): `facts` is an object keyed by manifest fact key, each `{state, value, reason}`. `state` is `ok` with the value (a missing file or systemd unit is `ok` with `null`), or `unreadable` or `unsupported` with a `reason` and a `null` value. The server checks each value against the manifest fact's type and limits, and refuses the whole report (`400 validation_failed`, a pointer per fact) if any does not fit. A fact the manifest lists that the report leaves out is recorded as missing; a key the manifest does not have is ignored and logged (DEC-08), as is an unknown field inside a fact. `manifest_version` is the manifest the agent collected against: newer than the server's is refused, older is fine. The response's `manifest_version` is the server's, so an agent can tell its copy is out of date.
- **Request IDs:** every response has an `X-Request-Id` header, and error bodies repeat it.

### Errors

Every `4xx` and `5xx` response has the body `{"error": {"code", "message", "request_id", "details"?}}` (`error.response`). A failed request never leaves a partial write. Agents should act on the HTTP status and treat any code they don't recognise by its status.

| Status | `code` | When |
|---|---|---|
| 400 | `validation_failed` | Body is not valid JSON or fails the schema or the server checks. `details` lists each field as a JSON Pointer |
| 401 | `unauthorized` | Credential missing, malformed, unknown, revoked, or for a retired host. Same body for each case |
| 403 | `reenrollment_required` | Valid credential, but the host is `pending` because an operator issued a new enrollment token (re-enrollment). The response also has the header `Fleet-Enrollment-State: pending`. The agent logs plainly that it must be re-enrolled (`fleet-agent install --reenroll`, or `--token` with the new token) and backs off to a long interval |
| 403 | `host_not_active` | Valid credential, but the host is in some other state that may not call this endpoint |
| 403 | `onboarding_rejected` | An operator rejected the onboarding request. The installer stops and says so |
| 404 | `not_found` | Unknown route, a release the server does not have, or a task that does not exist or belongs to another host (the same body for both) |
| 409 | `task_conflict` | A task result that differs from the one the server already has for the task, or that the task's state cannot take (for example `succeeded` for a task that never started). Logged and audited. The agent stops retrying that result |
| 410 | `enrollment_token_invalid` | Enrollment token unknown, expired, or already used. Same body for each case |
| 410 | `onboarding_expired` | Onboarding device code unknown, expired, or already used to collect a credential. Same body for each case; the installer starts again |
| 413 | `payload_too_large` | Body over the endpoint's size limit |
| 426 | `agent_version_unsupported` | `agent_version` is older than the server's minimum. The agent logs this plainly and backs off. Never sent by `heartbeat`, `update-results`, or the release downloads (the update path) |
| 429 | `rate_limited` | Too many requests, too many onboarding requests open, onboarding polled faster than its `interval`, or too many release downloads from one address. Honour the `Retry-After` header |
| 500 | `internal_error` | Unexpected failure. The message never contains internals |

P1-API-AUTH implements these. If it changes a code or status, it must update this table in the same pull request.

## Example data

Examples are public, so every value must be obviously fake. The server contract spec checks the following:

| Kind | Rule |
|---|---|
| Hostnames | Under `example.lan`, `example.com`, `example.net`, `example.org`, `.example`, `.test`, or `.invalid`, for example `vm-01.example.lan`. Any value under a `hostname` key must match this, including single-label names |
| IPv4 addresses | Documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| IPv6 addresses | Documentation range `2001:db8::/32` |
| Secrets | Any value under a `token`, `credential`, `secret`, `password`, or `device_code` key contains `EXAMPLE` |

Machine IDs, boot IDs, and report IDs use visibly patterned values, for example `0123456789abcdef0123456789abcdef` and `00000000-0000-4000-8000-000000000001`.

## Tests that guard the contract

The server contract spec (`cmdb/`) checks that:

- every schema is a valid draft 2020-12 schema
- every `valid/` example validates against its schema, and every `invalid/` example fails it
- **every property a schema declares, at every depth, appears in at least one `valid/` example**, so adding a field without an example fails CI
- every key in a `valid/` example is declared in the schema, which catches typos. The exception is examples named `unknown-field-*`, which exist to show that unknown fields are accepted
- examples contain no real hostnames, addresses, or credentials
- every schema has examples and every example directory has a schema

The agent contract test (`agent/`) validates the same examples with a Rust validator. Its helper, `assert_conforms(schema, value)`, is what agent tests use to check that serialised report structs match the schemas (P1-AGENT-REPORT, P1-ACCEPT).

Both CI workflows run when anything under `docs/api/` changes.

## Changing a schema

1. **Adding an optional field, or loosening a limit**, keeps old payloads valid. Edit the schema in place, then add or extend a `valid/` example that uses the field.
2. **Anything that could reject a payload an older agent sends**, or change what a field means, is a breaking change and needs a new schema version:
   1. Copy `schemas/v1/` to `schemas/v2/` and `examples/v1/` to `examples/v2/`, then make the change in `v2`. Never edit or delete files under an older version: they are the golden fixtures that later releases must keep accepting (NFR-5). Until Phase 3 is accepted, backward compatibility is not required (NFR-5), so `v1` may still change in place.
   2. Increase `AGENT_SCHEMA_VERSION` in `agent/src/main.rs`.
   3. Make the server accept both versions, selecting the schema by the `schema_version` in the body. Add a migration note to the PR describing how a v1 payload is read.
   4. Add a line to the change log below.
3. Run `bin/ci` in `cmdb/` and `cargo test` in `agent/`.

### Change log

| Version | Change |
|---|---|
| v1 | Initial Phase 1 payloads: enroll, heartbeat, inventory, errors (P0-CONTRACT) |
| v1 | Tightened before first release (review of #44): SemVer 2.0.0 `agent_version` (build metadata allowed, leading zeros rejected), timestamp patterns reject impossible month, day, hour, minute, and second values, `architecture` accepts `null` when unreadable, network addresses must be valid IPv4 (prefix 0-32) or IPv6 (prefix 0-128) CIDRs. No version bump: v1 has no released consumers. |
| v1 | `error.request_id` `maxLength` raised from 64 to 255, the length Rails accepts for an incoming `X-Request-Id` (P1-API-AUTH). Loosening only, so no version bump. |
| v1 | New error code `reenrollment_required` (403) with the `Fleet-Enrollment-State: pending` header, for endpoints a re-enrolling host may not call (P1-HEARTBEAT). Additive, so no version bump. |
| v1 | Onboarding endpoints and schemas (`onboarding.*`, `onboarding-token.*`) and error codes `onboarding_rejected` (403) and `onboarding_expired` (410) (P1-ONBOARD, DEC-17). Additive, so no version bump. |
| v1 | `enroll.response` gains the optional `host_name`, the name the operator gave the host, for the installer's summary; example `created-with-host-name.json` (P1-AGENT-INSTALL). Additive, so no version bump. |
| v1 | `warnings` may also explain a partly read list fact (`disks`, `network_interfaces`) that is not `null`; example `partial-lists.json` (P1-AGENT-COLLECT). Description only, so no version bump. |
| v1 | `heartbeat.response` `directives` is an object keyed by directive name instead of an always-empty array, with `intervals` defined and `agent_update` reserved as an object; the server sends `{}` (DEC-20, amending DEC-08). Breaking for the response shape, but v1 has no released agents, so no version bump. From here on a new directive or optional directive field is additive. |
| v1 | Release downloads `GET /api/v1/releases/<version>/manifest`, `signature`, and `binary`: unauthenticated, exempt from the minimum version, with `ETag`, `Content-Length`, and byte ranges (P1-RELEASES). New endpoints, so no version bump. |
| v1 | `heartbeat.response` `directives.agent_update` gains its fields (`rollout_id`, `version`, `manifest_url`, `signature_url`, `binary_url`, all required in the object), and `directives.intervals` is sent. New endpoint `POST /api/v1/update-results` with `update-result.request` and `update-result.response`. `heartbeat` and `update-results` are exempt from the `426` minimum-version check (P1-UPDATES, DEC-18). Additive, so no version bump: no agent has released and read `agent_update` before this. |
| v1 | New endpoint `POST /api/v1/reports/packages` with `packages.request` and `packages.response`, the only endpoint that takes `Content-Encoding: gzip` (P2-PACKAGES). New endpoint, so no version bump. |
| v1 | New endpoint `GET /api/v1/manifest/config` with `config-manifest.response`: the config fact manifest (P2-CONFIG-REPORTS, P2-S01). New endpoint, so no version bump. |
| v1 | New endpoint `POST /api/v1/reports/config` with `config.request` and `config.response`, which also takes `Content-Encoding: gzip` (P2-CONFIG-REPORTS, P2-S02). New endpoint, so no version bump. |
| v1 | `heartbeat.response` gains the `report_request` directive, `{"types": [...]}` with `types` required in the object, and examples `report-request*.json` (P2-CONFIG-REPORTS, P2-S03, DEC-13). Additive (DEC-20 rule 4), so no version bump: an agent that predates it ignores the name. |
| v1 | `packages.request` `manager` gains `unreadable` (reason required, in `unsupported_reason`; no packages) and the optional `skipped` array of `{name, reason}` (P2-S08, FR-2.3). Additive: an agent that sends neither is unchanged, so no version bump. Examples `unreadable-manager.json`, `skipped-packages.json`, and invalid ones for each rule. |
| v1 | `heartbeat.request` gains the optional `tasks` object (`catalog_version`, `supported`, `enabled`, `allowed_services`, `local_config`, all required in the object) and the heartbeat body limit rises from 4 KiB to 32 KiB; examples `tasks*.json` (P3-A01, FR-3.1). Additive: an agent that sends no `tasks` is unchanged, and is offered no task, so no version bump. |
| v1 | Task endpoints `POST /api/v1/tasks/poll`, `.../<id>/start`, `.../<id>/progress`, and `.../<id>/result` with `task-poll.*`, `task-start.*`, `task-progress.*`, and `task-result.*`; error code `task_conflict` (409); and the `tasks_available` heartbeat directive (P3-S03, P3-S04, FR-3.2). New endpoints and an additive directive, so no version bump. |
