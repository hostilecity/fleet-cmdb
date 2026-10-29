# P1-ONBOARD: Agent onboarding requests and endpoints

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Decided in [ADR 0017](../../decisions/0017-agent-onboarding.md). The dashboard side (approval page, "Awaiting approval" list) is [P1-D07](p1-dash-actions.md); the installer side is [P1-AGENT-INSTALL](p1-agent-install.md).

## P1-S14: Onboarding requests, start and collect endpoints

### Scope

- **Contract first.** Add `onboarding.request`, `onboarding.response`, `onboarding-token.request`, and `onboarding-token.response` schemas and examples under `docs/api`, and the new error codes to the table in `docs/api/README.md`. All of these are additive to v1, so no version bump.
- **Model.** An `onboarding_requests` table, kept apart from `hosts`. Columns:
  - the device code digest, and the user code as is: it is shown on the approval page so the operator can match it with the terminal, and it grants nothing without a signed-in operator (unique among open requests);
  - the reported facts: hostname, OS, machine ID, agent version;
  - the client address;
  - state: `open`, `approved`, `rejected`, or `collected`; "expired" is derived from the expiry time rather than stored;
  - the approving operator, and the host attributes the operator entered (name, tags, description, notes);
  - the re-enrollment target host, if any;
  - the expiry time.
- **`POST /api/v1/onboarding`.**
  - Unauthenticated, on the agent hostname only (DEC-05). The body is schema-validated and the reported text normalised as for inventory: control characters stripped, lengths capped.
  - Returns `device_code` (32 random bytes, encoded), `user_code` (8 characters from an unambiguous alphabet such as `BCDFGHJKLMNPQRSTVWXZ`, shown as `XXXX-XXXX`), `verification_uri` and `verification_uri_complete` (on the dashboard hostname), `expires_in` (default 600 seconds, configurable), and `interval` (default 5 seconds).
  - The device code is stored as a digest only.
- **`POST /api/v1/onboarding/token`** with `device_code`:
  - `202` with `{"status": "pending"}` while the request is open;
  - `429 rate_limited` when polled faster than `interval`;
  - `403 onboarding_rejected` after rejection;
  - `410 onboarding_expired` for an expired, unknown, or already-collected code (one body for all three);
  - `201` with the credential once approved.
- **Collection is one transaction under the request's row lock.** It marks the request `collected` and, for a new host, creates the host (`pending`), issues the credential, and activates it (FR-1.1). For a re-enrollment it replaces the target host's credential through the existing transitions. Audit entries name the approving operator and the host. A second collection attempt gets `410`.
- **Abuse limits.** Rate limit per client address on start (default 10 a minute). A cap on open requests, fleet-wide (default 50) and per address (default 5): above it the server answers `429` and creates nothing. Expired requests are pruned by a recurring job. Nothing creates a host before an operator approves.
- **Service objects for the dashboard:** `Onboarding::Approve` (operator, host attributes, and either "new host" or a target host) and `Onboarding::Reject`. Each is valid only on an `open`, unexpired request and is audited. Matching an existing host by machine ID or hostname is offered to the operator, never applied automatically.
- **Secrets.** Device codes, user codes, and credentials never appear in logs or audit entries. The request's log line uses its id.

### Acceptance criteria

- [ ] AC-1.8 (server half): start, approve, and collect issue exactly one credential, even under concurrent collect attempts, and the host appears with the operator's fields
- [ ] Rejected, expired, and never-collected requests leave no host record, and requests over the caps create nothing
- [ ] Approving as a re-enrollment of an active host keeps the old credential working until collection, then returns `401` for it (AC-1.5)
- [ ] Contract specs run every new example through the real endpoints, and no code or credential appears in captured logs
