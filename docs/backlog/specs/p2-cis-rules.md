# P2-CIS-RULES: Starter CIS-aligned rule set for Debian 13

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- A starter rule file for the distributions and benchmark versions chosen in [DEC-01](../../decisions/0001-fleet-profile.md) and [DEC-10](../../decisions/0010-cis-rules.md), covering the fact areas in the manifest: SSH, login and password policy, firewall, automatic updates, file permissions, services, local users.
- Written according to the [DEC-10](../../decisions/0010-cis-rules.md) decision: own wording, CIS section numbers as pointers only, no copied benchmark text (or kept outside the repository if the decision says so).
- Each rule has a fixture test with a passing and a failing fact set.
- A short guide: how to add or tune a rule, and the licensing note decided in [DEC-10](../../decisions/0010-cis-rules.md).
- UI and docs say "CIS-aligned", never "CIS compliant".

## Acceptance criteria

- [ ] The file validates and imports ([P2-S04](p2-cis-engine.md))
- [ ] Every rule has pass and fail fixtures that run in CI
- [ ] Licensing review against [DEC-10](../../decisions/0010-cis-rules.md) recorded in the PR
