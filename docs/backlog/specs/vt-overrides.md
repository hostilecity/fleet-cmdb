# VT-OVERRIDES: Operator decisions: record a control or accept a risk, with expiry, reason, and audit

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed); decided in [ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md). ADR 0022 left "per-finding risk acceptance" for a later decision; this is it. Drawn in [override.html](../../mockups/vuln-triage/override.html).

## VT-S06: Decisions

### Scope

- Table `finding_decisions`: host, advisory, kind (`control`, `accepted`), reason (10 to 1,000 characters, sanitised), expires on (a date), created by and at, ended by, at, and why (`operator`, `expired`, `fixed`, `suspended`, `resolved`), and the evidence at creation (bucket and rule, severity, KEV, EPSS band, vector, in-use class). One active decision per host and advisory, covering every binary package the advisory matches on the host. A decision is never deleted.
- Allowed only on findings in Needs attention or Low risk. Expiry at most `FLEET_DECISION_MAX_DAYS` (90), or `FLEET_DECISION_MAX_DAYS_KEV` (30) for a KEV-listed advisory (epic question 11).
- **Effect**: rule O1 or O2 (epic VT-M1) puts the finding in Low risk while the decision is active and not suspended. It never changes the finding's state or severity, and never removes it from the open count.
- **Ends by itself**: at expiry (a job every hour), when a fix appears (rule F1), or when every finding it covers resolves. **Suspended** by the triage run when the evidence gets worse than recorded: a CVE added to KEV, the EPSS band becoming high, or the severity rising. A suspended decision stays visible with why, and the finding falls through to N1 to N4 until someone records a new one.
- **Audit**, one action each (FR-S.3): `vulnerability.decision_recorded`, `vulnerability.decision_changed`, `vulnerability.decision_ended` (operator), `vulnerability.decision_expired`, `vulnerability.decision_suspended` (system, with the evidence that changed). Several hosts in one action are one audit entry per host plus a shared request id.
- **Re-classify** the hosts concerned in their transitions after each change (VT-S05).
- Second factor: not required (epic question 10, recommended), except one action covering more than 10 hosts, which uses the existing step-up (P3-S09).

### Acceptance criteria

- [ ] Recording a control moves the finding to Low risk with the reason and expiry shown, is audited with the evidence, and leaves the open count unchanged
- [ ] A decision ends at expiry and when a fix appears, and is suspended when its CVE is added to KEV, each audited by the system
- [ ] A decision longer than the limit, without a reason, or on a Fix available or Ignorable finding is refused with errors in place

## VT-D05: The flow

### Scope

- A page per decision, as the Phase 1 host actions: the form (kind, reason, until, applies to this host or the other hosts with the same open finding), the evidence now, errors in place, CSRF-protected POST; the saved notice with the score's change; change or end from the finding row.
- The Risk page's "Decisions due" lists suspended decisions, those expiring within 7 days, and Needs attention advisories without a decision.

### Acceptance criteria

- [ ] The form, errors, saved, and suspended states render as drawn, with labels and errors announced
- [ ] Every value an operator typed is escaped wherever it is shown, including the audit log
