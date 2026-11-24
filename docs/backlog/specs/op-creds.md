# OP-CREDS: Service credentials and the /api/operator/v1 boundary

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

**Proposed, awaiting the owner.** Nothing here is built until [ADR 0033](../../decisions/0033-operator-api.md) is accepted.

## OP-D01: Mockup of the service credentials page

Static HTML in `docs/mockups/operator-api/`, reusing `phase-1/mockup.css`: the list (name, scopes, created by, expires, last used, state), create (name, scopes as tick boxes, expiry) with the TOTP step-up, the credential shown once, revoke with confirmation, and the expired and revoked states. The owner approves it before the page is built.

## OP-S01: Service credential model and dashboard page

### Scope

- `ServiceCredential`: name, scopes (a fixed list: `hosts:preregister`, `hosts:read`, `compliance:read`, `hosts:retire`), digest and non-secret key id (same scheme as agent credentials, FR-S.1), created by (operator), expires at (default 90 days, at most 1 year), revoked at, last used at and from.
- Created, revoked and listed under Settings. Create and revoke need the TOTP step-up (DEC-06) and are audited. Scopes cannot be changed after creation; make a new credential instead.
- `rake service_credentials:create NAME=... SCOPES=... EXPIRES_IN=...` for the first one, printing the secret once.

## OP-S02: The /api/operator/v1 boundary

### Scope

- Routes under `/api/operator/v1` constrained to the agent hostname, like `/api/v1` (P1-S13); `404` on the dashboard hostname and on unknown hosts.
- `Authorization: Bearer <key id>.<secret>`; constant-time digest compare; expired or revoked credentials get `401` with the shared error shape; a missing scope gets `403 scope_required`.
- Per-credential rate limits, counted like the agent API's (FR-S.2).
- `docs/api/operator/README.md` with the endpoint table, and schemas and examples under `docs/api/operator/schemas/v1/` and `examples/v1/`, used by request specs as the agent API's are.

### Acceptance criteria

- [ ] A credential is shown once, stored only as a hash, refused after expiry or revocation, and refused for any endpoint outside its scopes (request specs)
- [ ] `/api/operator/v1` on the dashboard hostname returns 404, and creating or revoking a credential needs the TOTP step-up and writes an audit entry
- [ ] No secret appears in logs (spec over captured log output)
