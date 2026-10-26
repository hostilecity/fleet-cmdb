# ADR 0009: Repository visibility, license, and hygiene

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-09
- Requirements: `docs/requirements.md`

## Context

The repository is public, with no license, security policy, or `.gitignore`.

## Decision

The repository **stays public** under the **MIT license**. No real hostnames, addresses, certificates, keys, or fleet details are committed; docs, fixtures, and seeds use example values. Add `SECURITY.md`, a `.gitignore` covering IDE files, `.env*`, Rails `master.key`, and Rust `target/`, GitHub secret scanning with push protection, Dependabot, and branch protection on `main` once CI exists.

## Consequences

- The backlog issues, including the Phase 3 threat discussion, are public.
- CIS-derived content must follow ADR 0010.
