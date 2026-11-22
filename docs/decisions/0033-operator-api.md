# ADR 0033: A scoped operator API for provisioning tools

- Status: Proposed (awaiting the owner)
- Decision issue: DEC-33
- Requirements: `FR-S.6`, `FR-S.1`, `FR-S.3`, `NFR-1`

## Context

A provisioning tool on the LAN (the owner's homelab console in `hostilecity/op-works`, its ADR 0008) creates VMs that should enroll their agent on first boot with no one at a terminal. FR-S.1 already supports this through pre-registration, but only a signed-in operator in the dashboard can pre-register a host, and the only API is the agent API. The same tool needs to read a host's state and its CIS-aligned results (to gate a new VM image), and to retire the host when the VM is destroyed.

Section 1 puts VM provisioning out of scope. This decision does not change that: fleet-cmdb still provisions nothing. It lets an outside tool do through an API three things an operator already does in the dashboard.

## Decision

- **Where.** A second API, `/api/operator/v1`, served only on the private agent hostname, like `/api/v1`, and refused on the dashboard hostname. It is never routed through the tunnel. (Extends DEC-05's host separation to a third kind of route.)
- **Who.** Callers authenticate with a **service credential**: a named, long random secret, stored only as a hash with the same scheme as agent credentials (FR-S.1), with a non-secret identifier for lookup. A signed-in operator creates one in the dashboard after the TOTP step-up (DEC-06), sees it once, and sets an expiry (default 90 days, at most 1 year). It can be revoked at once. The first one may also be created by a rake task, like the first operator.
- **What.** Each credential carries a fixed set of scopes, chosen at creation and never widened later:
  - `hosts:preregister`: create a pre-registered host and receive its one-time enrollment token, or issue a new token for a pending host.
  - `hosts:read`: read a host's enrollment state, liveness, agent version, machine identifier and last seen.
  - `compliance:read`: read a host's CIS-aligned summary (score, counts, failing rule ids, evaluated at) and its vulnerability bucket counts.
  - `hosts:retire`: retire a host, which, as in the dashboard, also revokes its credential.

  There is no scope for tasks, rules, releases, rollouts, settings or operators. The operator API can never create a task or reach an agent (DEC-14).
- **Audit.** Every write (pre-register, new token, retire) and every credential change is an audit entry. The actor is the service credential, and the operator who created it is shown with it. Reads are not audited (they would flood the log). Each credential records when and from where it was last used.
- **Shape.** Same conventions as the agent API (DEC-08): JSON, versioned, strict validation, one error shape, per-credential rate limits. The contract lives in `docs/api/operator/`.

Rejected:
- **Calling the dashboard as a user** with a stored browser session: it is meant for people, sits behind Cloudflare Access, and has no scopes.
- **Exposing the operator API on the dashboard hostname** with an Access service token: it would put a host-creating API on the tunnel for a caller that is on the LAN anyway.
- **One all-powerful API key:** no least privilege, and a leaked key could do anything an operator can.

## Consequences

- A provisioning tool can pre-register, watch and retire hosts with no dashboard step, so unattended enrollment works for every new VM.
- A leaked service credential can create pending hosts and read fleet state, but cannot run anything on a VM or touch an existing host's credential. Expiry and revocation bound it.
- The dashboard gains a Settings page for service credentials (mockup first, OP-D01).
- Implemented by OP-CREDS, OP-HOSTS and OP-COMPLIANCE in the "Operator API" milestone, gated by Phase 2 acceptance like the vulnerability triage work, and not gating Phase 3.
