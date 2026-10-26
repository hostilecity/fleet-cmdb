# P2-CIS-ENGINE: CIS rule model, evaluator, and results

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-S04: CIS rule model, versioning, and file import

### Scope

- Rule storage per the [DEC-12](../../decisions/0012-rule-condition-format.md) format: stable rule key, version, reference, title, severity, applicability, fact, condition, remediation text, enabled flag.
- Rules are immutable per version: an edit creates a new version, and results record the version that produced them ([P2-S06](p2-cis-engine.md)).
- Import from a YAML file the operator controls (`rake rules:import FILE=...` and the dashboard upload in [P2-D06](p2-dash-fleet.md)): validated against the rule schema as a whole before anything is written; unchanged rules create no new version; changed rules create a new version; rules missing from the file are left unchanged unless an explicit flag disables them.
- Rule changes (add, edit, enable, disable) are audited with before and after values.
- Triggers re-evaluation of each host's latest snapshot after a change ([P2-S06](p2-cis-engine.md)).

### Acceptance criteria

- [ ] An invalid file imports nothing and reports every error
- [ ] Re-importing an unchanged file creates no versions
- [ ] Rule edits and toggles appear in the audit log
- [ ] Old versions remain readable

## P2-S05: Rule condition evaluator

### Scope

- A pure evaluator: `(rule, facts, host OS) -> {result, observed}` where result is `pass`, `fail`, `not_applicable`, or `not_readable`.
- Implements the operators from [DEC-12](../../decisions/0012-rule-condition-format.md) with no code evaluation of any kind. Regular expressions are anchored and time-limited so a hostile fact value cannot cause catastrophic backtracking.
- Applicability from `applies_to` against the host's distribution id and release.
- Unreadable or unsupported facts yield `not_readable` carrying the agent's reason; absent facts follow the operator semantics.
- The observed value is returned and stored with the result (truncated safely).

### Acceptance criteria

- [ ] Table-driven specs cover every operator for pass, fail, not applicable, and not readable
- [ ] A catastrophic-backtracking regex and an oversize value are handled within a time bound
- [ ] No use of `eval`, `instance_eval`, `send` on rule data, or shell invocation (checked by review and a lint rule or spec)

## P2-S06: Evaluation engine, results, and result history

### Scope

- Current result per host and rule (result, observed value, rule version, snapshot, evaluated at) and a history table of result **changes** (from, to, time, snapshot, rule version), so the dashboard can show a failure appearing and clearing without storing every evaluation.
- Background job evaluating a host's latest config snapshot against all enabled rules, run after each new snapshot.
- Re-evaluation job after a rule is added, edited, enabled, or disabled: re-runs the affected rule over each host's latest snapshot, with no agent contact. Disabled rules show as not evaluated.
- Per-host compliance summary computed from current results: passed, failed, not applicable, not readable, not evaluated.
- Idempotent and safe to run twice.

### Acceptance criteria

- [ ] AC-2.1: a changed SSH setting between two snapshots flips the related rule between pass and fail and records the change
- [ ] AC-2.2: editing a rule's expected value and re-evaluating changes results with no agent interaction
- [ ] AC-2.5: a fact that is unreadable makes the dependent results `not_readable` with the reason
- [ ] Re-running evaluation without changes writes no history rows
