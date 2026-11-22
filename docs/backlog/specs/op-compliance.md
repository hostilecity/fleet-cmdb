# OP-COMPLIANCE: Read a host's CIS-aligned summary and vulnerability buckets

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

**Proposed, awaiting the owner.** See [ADR 0033](../../decisions/0033-operator-api.md).

## Scope

- `GET /api/operator/v1/hosts/:id/compliance` (scope `compliance:read`): the latest evaluation's time, the CIS-aligned score, pass, fail and not-applicable counts, the ids of failing rules, and the vulnerability bucket counts from the per-host summaries ([ADR 0026](../../decisions/0026-dashboard-summaries-and-keyset-pages.md), [ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md)).
- Reads the same summaries as the dashboard, so the numbers cannot differ from the host's tabs.
- A host that has never been evaluated returns `"evaluated": false` and no counts.
- Rule ids only, never rule text (ADR 0010 wording rules stay inside the app).

## Acceptance criteria

- [ ] The numbers match the host's Configuration and Vulnerabilities tabs for the same evaluation (spec over fixtures)
- [ ] A host never evaluated returns an explicit not-evaluated state, not zeros
