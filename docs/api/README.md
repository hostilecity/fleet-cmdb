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
```

`<name>` is `<endpoint>.request` or `<endpoint>.response`. The directory version is the payload `schema_version`: everything under `v1/` is schema version 1.

## Endpoints

All endpoints are under `/api/v1`, served only on the private agent hostname ([DEC-05](../decisions/0005-hosting-tls-deployment.md)), and speak JSON over HTTPS.

| Endpoint | Auth | Request | Success |
|---|---|---|---|
| `POST /api/v1/enroll` | Enrollment token in the body | `enroll.request` | `201`, `enroll.response` |
| `POST /api/v1/heartbeat` | Bearer credential | `heartbeat.request` | `200`, `heartbeat.response` |
| `POST /api/v1/reports/inventory` | Bearer credential | `inventory.request` | `200`, `inventory.response` |

Later phases add the config, package, and task endpoints.

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
- **Missing facts:** a fact the agent cannot read is sent as `null`, with an entry in `warnings`. The report is still sent (FR-1.3).
- **Server checks beyond the schema:** some rules are not expressible in JSON Schema, such as free space not exceeding total. The server enforces these and answers `validation_failed`.
- **Request IDs:** every response has an `X-Request-Id` header, and error bodies repeat it.

### Errors

Every `4xx` and `5xx` response has the body `{"error": {"code", "message", "request_id", "details"?}}` (`error.response`). A failed request never leaves a partial write. Agents should act on the HTTP status and treat any code they don't recognise by its status.

| Status | `code` | When |
|---|---|---|
| 400 | `validation_failed` | Body is not valid JSON or fails the schema or the server checks. `details` lists each field as a JSON Pointer |
| 401 | `unauthorized` | Credential missing, malformed, unknown, revoked, or for a retired host. Same body for each case |
| 403 | `reenrollment_required` | Valid credential, but the host is `pending` because an operator issued a new enrollment token (re-enrollment). The response also has the header `Fleet-Enrollment-State: pending`. The agent logs plainly that the new token must be redeemed (`fleet-agent enroll --force`) and backs off to a long interval |
| 403 | `host_not_active` | Valid credential, but the host is in some other state that may not call this endpoint |
| 404 | `not_found` | Unknown route |
| 410 | `enrollment_token_invalid` | Enrollment token unknown, expired, or already used. Same body for each case |
| 413 | `payload_too_large` | Body over the endpoint's size limit |
| 426 | `agent_version_unsupported` | `agent_version` is older than the server's minimum. The agent logs this plainly and backs off |
| 429 | `rate_limited` | Too many requests. Honour the `Retry-After` header |
| 500 | `internal_error` | Unexpected failure. The message never contains internals |

P1-API-AUTH implements these. If it changes a code or status, it must update this table in the same pull request.

## Example data

Examples are public, so every value must be obviously fake. The server contract spec checks the following:

| Kind | Rule |
|---|---|
| Hostnames | Under `example.lan`, `example.com`, `example.net`, `example.org`, `.example`, `.test`, or `.invalid`, for example `vm-01.example.lan`. Any value under a `hostname` key must match this, including single-label names |
| IPv4 addresses | Documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| IPv6 addresses | Documentation range `2001:db8::/32` |
| Secrets | Any value under a `token`, `credential`, `secret`, or `password` key contains `EXAMPLE` |

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
