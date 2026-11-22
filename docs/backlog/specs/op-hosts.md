# OP-HOSTS: Pre-register, read and retire hosts through the operator API

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

**Proposed, awaiting the owner.** See [ADR 0033](../../decisions/0033-operator-api.md).

## Scope

| Endpoint | Scope | Result |
|---|---|---|
| `POST /api/operator/v1/hosts` | `hosts:preregister` | `201` with the host and its one-time enrollment token (FR-S.1 pre-registration: same lifetime, Pending state, audit entry). `409 host_exists` if a non-retired host has that hostname |
| `POST /api/operator/v1/hosts/:id/enrollment_token` | `hosts:preregister` | `201` with a new token for a pending host; the old token stops working. `409` for an active host (re-enrollment stays a dashboard action) |
| `GET /api/operator/v1/hosts?hostname=` and `GET /api/operator/v1/hosts/:id` | `hosts:read` | Enrollment state, liveness, agent version, machine identifier, first and last seen, tags |
| `POST /api/operator/v1/hosts/:id/retire` | `hosts:retire` | `200`; retires and revokes, as the dashboard does |

- Request: name, hostname, optional tags, description and notes (same validation as the dashboard form). Example hostnames use `vm-01.example.lan`.
- The token is in the response body only, once; never in a header, a log line or an audit value.
- The audit actor is the service credential; the entry also names the operator who created it.

## Acceptance criteria

- [ ] A host pre-registered through the API is indistinguishable from one pre-registered in the dashboard, except that the audit actor is the service credential
- [ ] The API never returns an agent credential, and a retired host's credential stops working at once (request specs)
- [ ] Issuing a new token for a pending host makes the old one fail at `POST /api/v1/enroll`
