# ADR 0010: Source and licensing of CIS rules

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-10
- Requirements: `docs/requirements.md`, section 10

## Context

CIS Benchmarks are CC BY-NC-SA 4.0 and CIS's non-member terms restrict derivative works, reposting, and claiming a compliance level. The repository is public. (To be verified; not legal advice.)

## Decision

Rules are written in **our own words**, using CIS section numbers only as references. Nothing is copied from CIS documents (titles, audit steps, remediation text). The UI and docs say **"CIS-aligned"** and "passes N of M checks", never "CIS compliant".

## Consequences

- Each starter rule is reviewed against this decision in its pull request.
- If any doubt remains, the rule file moves out of the repository and is imported at runtime.
