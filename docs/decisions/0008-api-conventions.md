# ADR 0008: Agent API conventions

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-08
- Requirements: `docs/requirements.md`, section 10

## Context

FR-S.2 left several choices open and NFR-5 needs a version-skew story.

## Decision

`Authorization: Bearer <credential_id>.<secret>`; unknown fields ignored and logged, wrong types and out-of-range values rejected; error shape `{error:{code,message,request_id}}`; `report_id` is a UUIDv4 reused on retry and `schema_version` is an integer; duplicate reports answered `200` with `duplicate: true`; HTTP 426 `agent_version_unsupported`; HTTP 429 with `Retry-After`; HTTP 413 for oversize; RFC 3339 UTC timestamps; heartbeat response `{server_time, directives: []}`. Endpoints: `POST /api/v1/enroll`, `/heartbeat`, `/reports/inventory`; later phases add config, packages, and task endpoints.

## Consequences

- Written up in `docs/api/README.md` by the SETUP-06 issue.
- `directives` is empty in Phase 1 and carries report requests (Phase 2) and task hints (Phase 3).
