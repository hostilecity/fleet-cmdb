# P2-VULNS: Advisory import and refresh, and vulnerability findings

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-S10: Advisory model and OSV import

### Scope

- Tables for advisories and their affected packages per [DEC-11](../../decisions/0011-vulnerability-data.md): advisory id, source, ecosystem (release scoped), package (source name), range events (introduced and fixed), severity (normalised and raw), reference URL, published, modified, and withdrawn.
- Importer for the chosen format (OSV JSON per [DEC-11](../../decisions/0011-vulnerability-data.md)) accepting a file, a directory, or an archive via `rake advisories:import`; idempotent by advisory id and `modified`; withdrawn advisories are retained and marked so existing findings resolve.
- Validation: reject malformed input without partial writes; cap file size; sanitise text; only `http` and `https` reference URLs are stored.
- Severity normalisation rule from [DEC-11](../../decisions/0011-vulnerability-data.md).
- Import audited (who, what source, counts).
- Triggers targeted re-matching ([P2-S11](p2-vulns.md)) for packages named in changed advisories.

### Acceptance criteria

- [ ] Re-importing the same data changes nothing
- [ ] Updated advisories replace older versions and trigger re-matching
- [ ] A malformed record is reported and does not prevent valid records from importing, or the whole file is rejected, as [DEC-11](../../decisions/0011-vulnerability-data.md) decides
- [ ] Reference URLs with other schemes are rejected

## P2-S13: Advisory feed refresh job and data freshness indicator

### Context

Stale vulnerability data fails silently: the dashboard would report zero findings while advisories are weeks old. [DEC-11](../../decisions/0011-vulnerability-data.md) chose a scheduled download of OSV data for `Debian:13`, with manual import as well.

### Scope

- Scheduled job fetching the configured advisory source (HTTPS, certificate verified), with size limits, conditional requests where supported, and the importer from [P2-S10](p2-vulns.md).
- Source configuration and any API key stored in Rails credentials or environment, never logged or shown.
- Dashboard shows "advisory data last updated" per ecosystem, with a clear warning when older than a configured threshold, and the same on [P2-D04](p2-dash-host.md) and [P2-D05](p2-dash-fleet.md).
- Failures retry with backoff and surface through the failed-jobs indicator ([P1-O02](p1-operability.md)).

### Acceptance criteria

- [ ] A failed or timed-out fetch retries and is visible to an operator
- [ ] The freshness warning appears when data is older than the threshold
- [ ] No secret appears in logs or error messages

## P2-S11: Vulnerability matching job and finding lifecycle

### Scope

- A host-to-ecosystem mapping from the inventory's distribution id and release (table maintained with the [DEC-01](../../decisions/0001-fleet-profile.md) fleet profile). Hosts with no mapping or no advisory data show "not evaluated" with the reason.
- Matching on source package name within the host's ecosystem, comparing the installed version to affected ranges with the manager's comparator ([P2-S09](p2-packages.md)). One finding per host, package, and advisory.
- Finding states: `open`, `resolved` (package updated past the fix or removed, or advisory withdrawn), and `reopened` (condition returns). Timestamps for first seen, resolved, and reopened.
- Runs in a background job triggered by a new package snapshot (that host only) and by advisory imports (affected packages only). Idempotent.
- Efficient for 50 hosts by 2,000 packages: indexed lookups by ecosystem and package, no per-package queries in loops.

### Acceptance criteria

- [ ] AC-2.4: importing an advisory for an installed version creates an open finding; after the package is updated on the VM and re-reported, the finding resolves
- [ ] A downgrade or reinstall of a vulnerable version reopens the finding
- [ ] Binary packages built from the same source package yield one finding per binary package actually installed (decision recorded and tested)
- [ ] Matching 50 hosts completes within the time budget recorded in the PR
