# ADR 0004: Enrollment flow

- Status: Accepted (owner, first requirements review); amended by [ADR 0017](0017-agent-onboarding.md): these tokens remain as pre-registration, alongside dashboard-approved onboarding
- Decision issue: DEC-04
- Requirements: `docs/requirements.md`

## Context

The draft mentions creating or approving a host and re-enrollment without defining how an agent first proves it may join.

## Decision

**Operator-issued single-use expiring token.** Creating a host yields a token (default 24 hours, stored as a digest); `fleet-agent enroll` redeems it for the permanent credential. Re-enrollment is a new token for the same host, and the old credential works until the new token is redeemed. There is no self-registration endpoint and no approval queue.

## Consequences

- The dashboard action is "create host"; there is nothing to approve.
- Credentials are `<key_id>.<secret>`, stored as a digest with a non-secret key id for lookup.
