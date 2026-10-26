# P1-API-AUTH: Agent API foundation, credentials, and enrollment

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-S06: API foundation: versioning, validation, errors, rate limits, size limits

### Scope

- `/api/v1` namespace, JSON only, with a base controller providing the behaviour below to all endpoints.
- Request validation against the JSON Schemas in `docs/api/schemas/` (for example with `json_schemer`), so the schema is the single source of truth. Unknown fields ignored and logged, per [DEC-08](../../decisions/0008-api-conventions.md); wrong types and out-of-range values rejected with details.
- Consistent error envelope with machine-readable code, message, and request id; mapping for validation, authentication, rate limit, oversize, unsupported version, and unexpected errors. Unexpected errors never leak internals.
- Per-credential rate limiting with `429` and `Retry-After` (Rails' built-in rate limiting is a good fit); limits configurable.
- Maximum request body size per endpoint, returning `413`.
- Minimum agent version check: the agent version in the request is compared to a setting; older agents get the dedicated error code ([DEC-08](../../decisions/0008-api-conventions.md)).
- Request id on every response and in logs.
- Atomicity helper: each write endpoint runs inside a single transaction so a failed request leaves nothing half-written.

### Acceptance criteria

- [ ] Every error path returns the documented envelope (table-driven spec)
- [ ] A malformed or oversize body is rejected without a database write
- [ ] A burst of requests from one credential is throttled while another credential is unaffected
- [ ] Sending an extra unknown field succeeds and is logged; sending a field with the wrong type fails
- [ ] A forced exception mid-request leaves no partial records

## P1-S04: Agent credentials and API authentication

### Scope

- `agent_credentials` table: host, non-secret key id, secret digest, state (active or revoked), created, revoked, last used.
- Generation: random secret (at least 32 bytes), presented to the caller exactly once as `<key_id>.<secret>`. Store a digest only (SHA-256 or keyed digest; not plaintext, not `has_secure_token`). Lookup by key id; compare with a constant-time function.
- API base controller: authenticates the `Authorization: Bearer` header, loads the host **through the credential** (`current_host`), and exposes no other way to find a host. Every API query is scoped to `current_host`.
- Revocation takes effect on the next request (no authentication caching). Revoked, unknown, malformed, or retired-host credentials all return the same `401` body so responses give no oracle.
- `last_used_at` updated cheaply (throttled so it is not a write per heartbeat).
- Revoke and rotate operations as service objects, each writing an audit entry ([P1-S03](p1-hosts.md)).

### Acceptance criteria

- [ ] AC-1.5: a revoked credential gets `401` on every endpoint, with a correct payload
- [ ] AC-1.6: a request authenticated as host A that supplies host B's identifier cannot read or modify B (request spec for every endpoint)
- [ ] The secret is never stored or logged (spec scans database rows and captured logs)
- [ ] Responses for unknown, revoked, and malformed credentials are indistinguishable

## P1-S05: Enrollment: one-time tokens, enroll endpoint, re-enrollment

### Scope

- `enrollment_tokens` table (host, digest, expires at, redeemed at). Tokens are random, single-use, expire (default 24 hours, configurable), and are stored as digests.
- Service to create a host and issue its first token, and to issue a **new** token for an existing host (re-enrollment). The token is returned once to the operator-facing caller. The dashboard flow is in [P1-D04](p1-dash-actions.md); this issue also adds rake tasks (`hosts:create`, `hosts:enroll_token`) so the flow is usable before the UI exists.
- `POST /api/v1/enroll`: unauthenticated apart from the token. Redeems the token in a single transaction: marks it used, creates the credential, moves the host `pending` to `active`, writes audit entries. The credential is returned once in the response.
- Re-enrollment: redeeming a new token for an `active` or `revoked` host replaces the credential; the old credential stays valid until that moment and is revoked in the same transaction.
- Stricter rate limiting per client address on the enroll endpoint, and identical error responses for unknown, expired, and used tokens.

### Acceptance criteria

- [ ] A token can be redeemed exactly once, including under concurrent requests
- [ ] An expired token cannot be redeemed
- [ ] After re-enrollment the old credential returns `401` immediately and the new one works
- [ ] The credential appears in the response body only once and never in logs or the audit log
- [ ] Specs cover each row of the FR-1.1 transition table that involves enrollment
