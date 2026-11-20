# VT-OVERRIDES: Operator decisions: record a control or accept a risk, with expiry, reason, and audit

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (approved by the owner, 2026-11-19); decided in [ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md). ADR 0022 left "per-finding risk acceptance" for a later decision; this is it. Drawn in [override.html](../../mockups/vuln-triage/override.html).

## VT-S06: Decisions

### Scope

- Table `finding_decisions`: host, advisory, kind (`control`, `accepted`), reason (10 to 1,000 characters, sanitised), expires on (a date), created by and at, ended by, at, and why (`operator`, `expired`, `fixed`, `suspended`, `resolved`), and the evidence at creation (bucket and rule, severity, KEV, EPSS band, attack vector, listening class). One active decision per host and advisory, covering every binary package the advisory matches on the host. A decision is never deleted.
- Allowed only on findings in Needs attention or Low risk. Expiry at most `FLEET_DECISION_MAX_DAYS` (90), or `FLEET_DECISION_MAX_DAYS_KEV` (30) for a KEV-listed advisory (epic decision 15).
- **Effect** (S1, epic decision 12):
  - **Control in place** (rule O1) moves the finding to Low risk, scored as "Low risk by a control" (10, 5, 2, 1 points; KEV doubled), well above plain Low risk. A KEV-listed finding under a control keeps the "Known exploited" tier.
  - **Risk accepted** changes no bucket, points, or tier. The finding stays where the rules put it (normally Needs attention), marked "risk accepted until ...", and leaves "decisions due". Accepting a risk changes nothing about exposure, so it never lowers the score.
  - Neither changes the finding's state or severity, or removes it from the open count.
- **Ends by itself**: at expiry (a job every hour), when a fix appears (rules K1, K2, F1, F2), or when every finding it covers resolves. **Suspended** by the triage run when the evidence gets worse than recorded: a CVE added to KEV, the EPSS band becoming high, or the severity rising. A suspended control stops applying (the finding falls through to N1 to N4); a suspended acceptance returns the finding to "decisions due". Both stay visible with why.
- **Several hosts** (N8): one action may cover several hosts with the same open finding, but each host shows its own evidence, and a control must be confirmed host by host (a checkbox per host saying the control exists there). An acceptance may cover them together. Each host gets its own decision and audit entry, with a shared request id.
- **Audit**, one action each (FR-S.3): `vulnerability.decision_recorded`, `vulnerability.decision_changed`, `vulnerability.decision_ended` (operator), `vulnerability.decision_expired`, `vulnerability.decision_suspended` (system, with the evidence that changed).
- **Re-classify** the hosts concerned in their transitions after each change (VT-S05).
- Second factor: not required (epic decision 14), except one action covering more than 10 hosts, which uses the existing step-up (P3-S09).
- Adds the decision links and tags to the host tab (VT-D04).

### Acceptance criteria

- [ ] A control moves the finding to Low risk with its reason and expiry shown and its points as "by a control"; an acceptance keeps the finding's bucket, points, and tier; both are audited with the evidence and leave the open count unchanged
- [ ] A decision ends at expiry and when a fix appears, and is suspended when its CVE is added to KEV, each audited by the system
- [ ] A decision longer than the limit, without a reason, on a Fix available or Ignorable finding, or a control not confirmed for a host, is refused with errors in place

## VT-D05: The flow

### Scope

- A page per decision, as the Phase 1 host actions: kind, reason, until, the hosts it applies to (each with its evidence and, for a control, a confirmation), errors in place, CSRF-protected POST; the saved notice with the score's change (or "no change" for an acceptance); change or end from the finding row.
- The Risk page's "Decisions due" lists suspended decisions, decisions expiring within 7 days, and Needs attention advisories with no decision (accepted ones are not "due").

### Acceptance criteria

- [ ] The form, errors, saved, and suspended states render as drawn, with labels and errors announced
- [ ] Every value an operator typed is escaped wherever it is shown, including the audit log
