# P2-CIS-RULES: Starter CIS-aligned rule set for Debian 13

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- A starter rule file for the distributions and benchmark versions chosen in [DEC-01](../../decisions/0001-fleet-profile.md) and [DEC-10](../../decisions/0010-cis-rules.md), covering the fact areas in the manifest: SSH, login and password policy, firewall, automatic updates, file permissions, services, local users.
- Written according to the [DEC-10](../../decisions/0010-cis-rules.md) decision: own wording, CIS section numbers as pointers only, no copied benchmark text (or kept outside the repository if the decision says so).
- Each rule has a fixture test with a passing and a failing fact set.
- A short guide: how to add or tune a rule, and the licensing note decided in [DEC-10](../../decisions/0010-cis-rules.md).
- UI and docs say "CIS-aligned", never "CIS compliant".
- Delivered as `cmdb/config/rules/debian-13.yml`: 71 rules covering every fact area of the manifest (20 SSH, 13 login and password policy, 1 local users, 2 firewall and automatic updates, 19 file permissions, 4 services that should run, 12 that should not). References name sections of the CIS Debian Linux 13 Benchmark v1.0.0, checked against the public listing of its section numbers; where no single section matches (or the number could not be confirmed), the reference names the parent section. Hand-chosen pass and fail values for every rule, with edge cases, are in `cmdb/spec/fixtures/cis_rules/debian-13.yml`, checked by `cmdb/spec/rules/debian_13_rules_spec.rb` (the file validates and imports, every fixture is a valid value for its fact, every rule passes and fails as its fixtures say), which also checks the wording rules and the repository for a CIS compliance claim. Time synchronisation and the choice of firewall need two facts in one rule, which DEC-12 does not allow, so they have no rule yet. Each title claims only what its one fact shows; where that is part of a policy (PAM's hashing method, `minlen` with positive credits, keyboard-interactive logins), the remediation says what else to check, and positive `pwquality` credits have their own rules (review of #112). The guide is [docs/operations/cis-rules.md](../../operations/cis-rules.md). The `docs/api/rules` README example now cites 5.1.21, the PermitRootLogin section in v1.0.0 (5.1.20 is PermitEmptyPasswords).

## Acceptance criteria

- [ ] The file validates and imports ([P2-S04](p2-cis-engine.md))
- [ ] Every rule has pass and fail fixtures that run in CI
- [ ] Licensing review against [DEC-10](../../decisions/0010-cis-rules.md) recorded in the PR
