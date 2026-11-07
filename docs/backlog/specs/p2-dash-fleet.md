# P2-DASH-FLEET: Dashboard: fleet compliance and rule management

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-D05: Fleet compliance view and fleet-wide severity counts

### Scope

- A table of every active host with its CIS pass rate, open CIS failures by severity, and open vulnerability findings by severity; sortable and filterable by tag.
- Fleet-wide counts of open findings by severity at the top, and a link or summary from the Phase 1 fleet list.
- Hosts that are not evaluated are visibly distinct from hosts with no findings.
- Efficient queries (no N+1, aggregated in the database).

### Acceptance criteria

- [ ] Loads in under 2 seconds with 50 hosts ([P2-S12](p2-accept.md))
- [ ] Counts match the underlying findings and results (spec)
- [ ] "Not evaluated" and "zero findings" are never shown the same way

## P2-D06: Rules and data sources management UI

### Scope

- Rules: list with filters, rule detail with version history, add one rule from a form (a single comparison; a rule with several conditions comes in by importing a file), edit the condition and metadata with validation in place, a preview of which hosts would change result before a new rule or an edit is saved (Add rule or Edit, then Preview, then Save; uses the dry run in [P2-S14](p2-rule-dryrun.md); an unchanged definition previews as "no change"), enable and disable (with confirmation), upload a rules file with a preview of what would change before applying.
- Advisory data: show sources, last import, counts per ecosystem, upload an advisory file, trigger a manual feed refresh if [P2-S13](p2-vulns.md) exists, with the cool-down of [P2-S15](p2-refresh-limit.md) (the button is disabled and shows when it is available again).
- Every change audited with the operator as actor; edits show before and after.
- Rules delivered as `RulesController`, `RuleVersionsController`, and `RuleImportsController` (`cmdb/app/views/rules`, `rule_versions`, `rule_imports`), with `RuleList`, `RuleResults`, `RuleForm`, `CisRules::ImportPlan`, and `RuleImportPreview`; the **Rules** item in the top bar. The list filters by text, severity, status, distribution and release, and fleet result, sorts by name, severity, or status, and pages by 50. The rule page shows results on every host in the fleet, the versions (each readable at `/rules/:id/versions/:n`, with what differs in the current one, when it was current, and whether a current result still uses it), and the change log from the audit entries with before and after values. Add and edit are form, Preview, Save: Preview is a POST that writes nothing (the rule built by `RuleForm`, checked by `CisRules::RuleFile.parse_rule`, previewed by `CisDryRun`); the preview page carries the typed fields, so Save saves the rule that was previewed, checked again, through `CisRule.define!` with the operator as actor, and every host is re-evaluated by `CisEvaluationJob` with no agent contact. A single comparison (`eq`, `ne`, `in`, `not_in`, `gte`, `lte` on the fact itself) is an operator and an expected value read by the fact's type; any other condition is edited as YAML or JSON text. Every problem is listed at the top and beside its field, with its JSON Pointer when it points inside the field. Adding refuses a key in use; an edit is refused (409, the typed values kept) if another version was saved after it began. Enable and disable are a confirmation page and a POST; the disable page names the hosts whose failures drop out. Every rule change (import, add, edit, enable, disable) runs under `CisRule.with_write_lock`. Each rule's audit entries record where the change was made (`source`: `file_upload`, a rules file uploaded in the dashboard; `dashboard`, the add and edit form and the enable and disable buttons; `rules_import`, the rake task), on creation, every later version, and enable and disable, so the change log says "Created from a rules file import", "Created in the dashboard", or "Created by rules:import" (and "Edited ...", "Disabled ..." alike); an entry recorded before sources has none and reads "Created, version 1".
- Owner decisions on #130 (deviations from the mockups, accepted): "Add another distribution" is an always-present empty row, not a link; the edit errors page's button is "Preview the effect" (Q12 puts a preview before every save); the pager reads "Previous · Next" (rules sort by name); the import page names `docs/api/rules/README.md` as text, and the mockup's "Other ways a file is refused" examples are not built; confirmations are their own pages, as the Phase 1 host actions; the edit form offers only facts a single comparison can test, and a file or service rule is edited as text with every fact offered; the add-rule preview words the hosts it does not apply to from the rule's own applies to ("1 host is not debian 13"). The import store and "refuse, then preview again" are approved as built.
- The import preview's file store (owner decision Q13) is the `rule_import_previews` table, not files: only a file that passed every check, at most 1 MiB (a check constraint too), one per operator (a later upload replaces it), named by a random token and found only for its operator, expiring 15 minutes after the preview, deleted on apply, cancel, or replacement, and pruned every 5 minutes by `RuleImportPreviewPruneJob`. It keeps `CisRule.state_digest` from the preview; Apply passes it to `CisRules::Import` as `expected_state`, checked under the write lock, so if any rule was added, edited, enabled, or disabled since, nothing is written and the page previews the same file again against the rules as they are now, saying why (409). A file the checks refuse at apply (a new fact manifest) lists its problems and is discarded.

### Acceptance criteria

- [ ] AC-2.2: editing a rule's expected value in the UI re-evaluates and changes results with no agent contact
- [ ] Invalid edits are rejected with errors in place
- [ ] A second manual feed refresh within 5 minutes is refused by the server, and the button shows the time left
- [ ] Adding a rule creates version 1 through the same checks as import, re-evaluates every host, and is audited
- [ ] The edit preview lists the hosts whose result would change, with before and after, and writes nothing
- [ ] The add-rule form previews the new rule's results (pass, fail, and the hosts it does not apply to or that have no config report) before saving, and writes nothing
- [ ] The import preview lists adds, changes, and unchanged rules before anything is written
