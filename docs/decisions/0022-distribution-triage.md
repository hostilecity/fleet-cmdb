# ADR 0022: Show the distribution's own triage beside each finding

- Status: Accepted (owner, 2026-11-07)
- Decision issue: DEC-22
- Requirements: `FR-2.4`, `FR-2.5`
- Extends: [ADR 0011](0011-vulnerability-data.md), which chose OSV for affected ranges, fixes, and severity. Nothing in it is reversed.

## Context

An OSV record for a Debian CVE carries the CVE's CVSS v3 vector, and ADR 0011's severity rule scores it first. Debian's security team often judges the same CVE differently for a release. For example, CVE-2026-19499 (glibc) is High by its CVSS score, but the tracker notes `<no-dsa> (Minor issue)` for trixie and `<postponed>` for bookworm. The package is still vulnerable there, so the finding is correct, but the dashboard shows nothing of Debian's view, and an operator reads a High with no context.

The Debian Security Tracker publishes all of its data as one JSON document (`https://security-tracker.debian.org/tracker/data/json`), keyed by source package, then CVE, then release, with each release's status, urgency, fixed version, and any no-DSA note. Agents already report each package's source package, so the data joins on what the server already stores.

## Decision

1. The server imports the Debian Security Tracker's JSON as a **second advisory data source beside OSV**, on the same schedule, with its own freshness. It is one file per refresh, fetched with a conditional request, never per host or per CVE.
2. Its data is an **annotation**: Debian's status, urgency, and no-DSA or postponed note for a CVE, a source package, and a release. It is shown beside each finding, on the host's vulnerabilities tab, the package page, and the data sources page.
3. It **does not change** a finding's state (open, resolved, reopened) or its normalised severity. OSV stays the only source of affected ranges, fixes, and severity, so the counts and the severity rule of ADR 0011 are unchanged. Letting a distribution's triage lower a severity, and per-finding risk acceptance, are separate decisions for later.
4. Nothing in the design assumes Debian 13 or one distribution: a release is mapped from the host's inventory (`ID`, `VERSION_ID`) to the source's release name by a table, and the source is one of possibly several triage sources, so other Debian releases and other distributions' trackers can be added after the MVP.

## Consequences

- One more outbound HTTPS destination (`security-tracker.debian.org`), which can be turned off; findings then show that Debian's triage is not available.
- The data can be stale or missing for a CVE. The dashboard says so rather than implying Debian has no opinion.
- Debian asks automated clients to fetch the file sparingly. A 6-hour schedule with a conditional request keeps within that.
