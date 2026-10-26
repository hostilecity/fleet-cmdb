# ADR 0007: Snapshot semantics and retention

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-07
- Requirements: `docs/requirements.md`, section 10

## Context

"Materially changes" was undefined, and append-only audit entries conflicted with pruning.

## Decision

Inventory fields are **stable** or **volatile**. Only stable-field changes trigger an extra report and create a snapshot; volatile values update current state on every report. Retried reports are deduplicated by report id. Snapshots and status history are retained 90 days (configurable) and the newest per host and type is always kept. **Audit entries are never auto-pruned.**

## Consequences

- The stable and volatile lists are in FR-1.3.
- A separate audit-pruning setting is not built unless wanted later.
