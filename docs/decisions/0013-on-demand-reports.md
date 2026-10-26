# ADR 0013: On-demand report request

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-13
- Requirements: `docs/requirements.md`, section 10

## Context

FR-2.1 needs an operator-triggered report but agents only pull and tasks arrive in Phase 3.

## Decision

The dashboard sets a "report requested" flag; the next heartbeat response carries it as a **directive**; the agent reports once and the request clears when a newer report arrives. Requests are rate limited and audited. The Phase 3 `refresh_reports` task reuses this mechanism.

## Consequences

- Latency is up to one heartbeat interval.
- An older agent that ignores directives is unaffected.
