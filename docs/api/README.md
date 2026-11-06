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
| `GET /api/v1/manifest/config` | Bearer credential | none | `200`, `config-manifest.response`, or `304` |
| `POST /api/v1/update-results` | Bearer credential | `update-result.request` | `200`, `update-result.response` |
| `GET /api/v1/releases/<version>/manifest`, `.../signature`, `.../binary` | None (agent hostname only, rate-limited per address) | none | `200` (or `206`, `304`, `416`), the release file's bytes |

Later phases add the config and task endpoints.

### Updates

The scope change in #54 ([DEC-17](../decisions/0017-agent-onboarding.md), [DEC-18](../decisions/0018-signed-agent-updates.md)) adds two pieces to the contract, built by P1-UPDATES:

- **The `agent_update` directive** in `heartbeat.response` (below): the rollout, the version, and the three URLs to fetch it from.
- **`POST /api/v1/update-results`:** the agent reports `succeeded`, `failed`, or `rolled_back` (with a `reason`) for a rollout, with a `report_id` reused on retry; a retried result is answered `200` with `duplicate: true`. `400 validation_failed` also covers a `rollout_id` the host is not part of and a `version` that is not the rollout's release (the `details` pointer names the field). A `failed` or `rolled_back` result halts the rollout.

**The update path never sees `426`** (FR-S.5, DEC-18). Heartbeats, update results, and release downloads are exempt from the minimum agent version, so an agent that is too old for everything else can still heartbeat, receive the directive, download the release, and report the outcome. Every other endpoint, reports included, still answers `426 agent_version_unsupported` to it; the agent does not read directives from a `426`, so the server sends none there. The test `spec/requests/api/update_path_spec.rb` (P1-X01) guards this and is kept in every later phase.

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
- **Compression:** `POST /api/v1/reports/packages` also takes a body sent with `Content-Encoding: gzip`. Its 4 MiB limit applies to the body as JSON, sent plain or once decompressed; a compressed body may be at most 1 MiB on the wire, like every other request. Every other endpoint, and any other encoding, answers `400 validation_failed`.
- **Package reports** (FR-2.3): `manager` is `dpkg`, or `unsupported` with an `unsupported_reason` and no packages, so a host whose packages cannot be listed is never shown as having none. Each package has its `name`, `version` exactly as dpkg records it (with any epoch; any printable ASCII without spaces, so a version dpkg only warns about is still reported), `architecture`, and `source` package (`null` when dpkg records none). A name and architecture appear at most once (`400 validation_failed` with the pointer otherwise). Versions are compared with dpkg's rules, never as strings (FR-2.4).
- **Config fact manifest** (FR-2.1): the versioned list of facts an agent may report, with each fact's key, type, `since` version, and limits. It names fact keys only, never commands. It carries no agent version, so it is exempt from `426`, and it is sent with a strong `ETag` (`If-None-Match` gives `304`). How to add a fact: [config-facts.md](../operations/config-facts.md).
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
| 404 | `not_found` | Unknown route, or a release the server does not have |
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
   1. Copy `schemas/v1/` to `schemas/v2/` and `examples/v1/` to `examples/v2/`, then make the change in `v2`. Never edit or delete files under an older version: they are the golden fixtures that later phases must keep accepting (NFR-5, P1-ACCEPT).
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
