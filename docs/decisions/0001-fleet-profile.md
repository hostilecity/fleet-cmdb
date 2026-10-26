# ADR 0001: Fleet profile

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-01
- Requirements: `docs/requirements.md`, section 10

## Context

The agent is a static binary and Phase 2 content (config facts, rules, package versions, advisories) is distribution-specific.

## Decision

The fleet is **Debian 13 on x86_64 with systemd and dpkg/apt**. The agent builds for `x86_64-unknown-linux-musl` only. Collectors, CIS rules, version comparison, and advisory matching target Debian 13 only.

## Consequences

- rpm and apk collectors and comparators are not built; adding a distribution or architecture needs a new decision.
- Phase 2 issues for version comparison and package collection are narrowed to dpkg.
- CI integration tests run against a Debian 13 image.
