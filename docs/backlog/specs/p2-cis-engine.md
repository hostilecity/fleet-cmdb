# P2-CIS-ENGINE: CIS rule model, evaluator, and results

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-S04: CIS rule model, versioning, and file import

### Scope

- Rule storage per the [DEC-12](../../decisions/0012-rule-condition-format.md) format: stable rule key, version, reference, title, severity, applicability, fact, condition, remediation text, enabled flag.
- Rules are immutable per version: an edit creates a new version, and results record the version that produced them ([P2-S06](p2-cis-engine.md)).
- Import from a YAML file the operator controls (`rake rules:import FILE=...` and the dashboard upload in [P2-D06](p2-dash-fleet.md)): validated against the rule schema as a whole before anything is written; unchanged rules create no new version; changed rules create a new version; rules missing from the file are left unchanged unless an explicit flag disables them.
- Rule changes (add, edit, enable, disable) are audited with before and after values.
- Triggers re-evaluation of each host's latest snapshot after a change ([P2-S06](p2-cis-engine.md)).
- Delivered as `CisRule` and `CisRuleVersion` (`cis_rules`, `cis_rule_versions`), `CisRules::RuleFile` and `CisRules::Condition` (`cmdb/lib/cis_rules`), `CisRules::Import`, and `bin/rails rules:import FILE=... [DISABLE_MISSING=1]` and `rules:list` (`cmdb/README.md`, "CIS-aligned rules"). The format and its schema are in `docs/api/rules` (format 1), outside the agent API contract because agents never see rules; the image copies it in from the same build context. A file is read as plain YAML (no objects, aliases, or dates; at most 1 MiB), checked against the schema, then each rule against the fact manifest: unique keys, a known fact, operators that fit the fact's type, operands that fit the value (an unquoted YAML `no` is refused with a hint), patterns that compile on their own, at most 64 condition parts nested 8 deep. Every problem is listed with a JSON Pointer (up to 200). The `enabled` flag changes only when the file states it, so a re-import does not undo a toggle. A version is numbered from 1, read-only once written, and created only when the definition's content hash changes (keys sorted, so key order in the file does not matter). Audit actions `rule.created`, `rule.edited` (changed fields before and after, and the version), `rule.enabled`, and `rule.disabled`, shown on the audit page by the rule's key. The dashboard upload is P2-D06. Every change re-evaluates the rule on every host once it commits (P2-S06).

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
- Delivered as `CisRules::Evaluator.call(rule, facts, os)` (`cmdb/lib/cis_rules/evaluator.rb`), returning `Outcome(result, observed, reason)`. It reads nothing but its arguments: a rule version (or definition), the facts as a config snapshot will store them (`{key => {state, value, reason}}`, a missing key meaning missing; P2-S02), and the host's os-release `id` and `version_id`. In order: no operating system reported is `not_readable`; `applies_to` not matching is `not_applicable`, with a reason naming both; an unreadable, unsupported, or missing fact is `not_readable` with the agent's reason; a value that does not fit the manifest (wrong type, oversize) is `not_readable` rather than evaluated; otherwise `pass` or `fail` with the value as reported. Lists are compared as the manifest says (sorted unless `ordered`). A missing file or unit (the only null the manifest allows) passes only `absent`, `ne`, and `not_in`, so `present` and `absent` are now refused on other facts at import. Patterns are anchored and limited to 50 ms per match and 250 ms per rule; running out of time is `not_readable`. The observed value is kept as reported up to 1 KiB of JSON, otherwise cut at a character boundary and marked truncated; reasons are cut at 512 characters. Operators are dispatched from the closed list with `case`; a spec reads the rule code's Ruby tokens and fails on `eval`, `send`, `public_send`, `constantize`, backticks, `system`, and the like.

### Acceptance criteria

- [ ] Table-driven specs cover every operator for pass, fail, not applicable, and not readable
- [ ] A catastrophic-backtracking regex and an oversize value are handled within a time bound
- [ ] No use of `eval`, `instance_eval`, `send` on rule data, or shell invocation (checked by review and a lint rule or spec)

## P2-S06: Evaluation engine, results, and result history

### Scope

- Current result per host and rule (result, observed value, rule version, snapshot, evaluated at) and a history table of result **changes** (from, to, time, snapshot, rule version), so the dashboard can show a failure appearing and clearing without storing every evaluation.
- Background job evaluating a host's latest config snapshot against all enabled rules, run after each new snapshot.
- Re-evaluation job after a rule is added, edited, enabled, or disabled: re-runs the affected rule over each host's latest snapshot, with no agent contact. Disabled rules show as not evaluated.
- A dry run of an edited or new rule, for the edit preview, is [P2-S14](p2-rule-dryrun.md).
- Per-host compliance summary computed from current results: passed, failed, not applicable, not readable, not evaluated.
- Idempotent and safe to run twice.
- Delivered as `CisEvaluation` (`cmdb/app/services/cis_evaluation.rb`), `CisEvaluationJob`, and `CisCompliance`, with `cis_results` (current result per host and rule: result, observed value, reason, rule version, snapshot, evaluated and changed times) and `cis_result_changes` (from, to, time, snapshot, rule version, observed value, reason; written only on a change, so a re-run writes none, and the database refuses a row that is not a change). The job runs for a host after a new config snapshot, and also when the host's operating system changes or is first known, since `applies_to` depends on it (otherwise a host whose first inventory arrived after its config report would stay not_readable until its facts changed). It runs for a rule on every host after `CisRule` creates, versions, enables, or disables it, so imports and the dashboard both re-evaluate. Results are `not_evaluated` for a disabled rule (with no version or snapshot) and for every rule on a host that has sent no config report; the compliance summary counts a rule with no result yet as not evaluated, so its counts always add up to the number of rules. Each host is evaluated in its own transaction under its row lock, as agent writes take it, so a report in progress is waited for and concurrent runs write each change once. The rules, snapshot, and evaluation time are read once the lock is held, so a run that waited never writes an older rule's result over a newer one or dates a change before the one it follows; the compliance summary counts results only for the rules it read. Snapshot ids on results and changes are cleared, not blocking, when Retention prunes a snapshot; changes are pruned after the retention window, current results never.

### Acceptance criteria

- [ ] AC-2.1: a changed SSH setting between two snapshots flips the related rule between pass and fail and records the change
- [ ] AC-2.2: editing a rule's expected value and re-evaluating changes results with no agent interaction
- [ ] AC-2.5: a fact that is unreadable makes the dependent results `not_readable` with the reason
- [ ] Re-running evaluation without changes writes no history rows
