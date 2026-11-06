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
- Malformed input, decided here because [DEC-11](../../decisions/0011-vulnerability-data.md) does not say: OSV publishes one record per file, so a malformed record is reported (where, which id, why) and skipped, and the valid records import. A record never imports in part. Input that cannot be read at all (an unreadable archive, a broken limit) imports nothing.
- Delivered as `Advisories::Import`, `Advisories::Reader`, `Advisories::Record`, and `Advisories::Severity` (`cmdb/app/services/advisories`), `bin/rails advisories:import FILE=... [FULL=1]` and `advisories:status`, and the tables `advisories`, `advisory_packages` (one row per advisory, ecosystem, and source package, with the OSV `ECOSYSTEM` ranges' events, indexed by ecosystem and package), and `advisory_imports` (`cmdb/README.md`, "Advisory data").
  - **Ecosystems.** `Ecosystems` (`cmdb/app/models/ecosystems.rb`) is the fleet-profile table, built here because the importer keeps only its ecosystems: `debian` `13` → `Debian:13`. Records for other ecosystems are skipped.
  - **Transactions and limits.** One transaction per import, under an advisory lock. Each document is read to at most 2 MiB; an archive may be at most 512 MiB (`FLEET_ADVISORY_MAX_DOWNLOAD_MB`), a million documents, and 8 GiB of JSON.
  - **Stored values.** Text has control characters removed and a length cap; summaries are at most 512 characters. Ids, package names, and range versions are pattern-checked; whether dpkg can parse a version is left to matching.
  - **Severity rule.** A CVSS v3 base score (computed from the vector, banded as CVSS bands it), then `database_specific.severity`, then a Debian urgency, else unknown. The raw value is kept. v2 and v4 vectors are kept as raw but not scored.
  - **Withdrawn and absent advisories.** Withdrawn advisories are kept and marked. A full import (the refresh, or `FULL=1`) also marks advisories it does not contain as withdrawn (`absent`), because OSV moves withdrawn records out of an ecosystem's archive, so the archive alone would never withdraw anything. This was added beyond the original scope. The sweep is skipped when any record was malformed.
  - **Re-matching.** The import returns the packages that changed advisories name, before and after. The call to matching is added with [P2-S11](#p2-s11-vulnerability-matching-job-and-finding-lifecycle).
  - **Measured** (sandbox, PostgreSQL on the same machine), with a synthetic 60,000-record archive of 29.5 MiB, 40,000 records for `Debian:13`: a first import took 25 s, and re-importing it, which changed nothing, took 14 s.

### Acceptance criteria

- [ ] Re-importing the same data changes nothing
- [ ] Updated advisories replace older versions and trigger re-matching
- [ ] A malformed record is reported and does not prevent valid records from importing (decided above, since [DEC-11](../../decisions/0011-vulnerability-data.md) does not decide it)
- [ ] Reference URLs with other schemes are rejected

## P2-S13: Advisory feed refresh job and data freshness indicator

### Context

Stale vulnerability data fails silently: the dashboard would report zero findings while advisories are weeks old. [DEC-11](../../decisions/0011-vulnerability-data.md) chose a scheduled download of OSV data for `Debian:13`, with manual import as well.

### Scope

- Scheduled job fetching the configured advisory source (HTTPS, certificate verified), with size limits, conditional requests where supported, and the importer from [P2-S10](p2-vulns.md).
- Source configuration and any API key stored in Rails credentials or environment, never logged or shown.
- Dashboard shows "advisory data last updated" per ecosystem, with a clear warning when older than a configured threshold, and the same on [P2-D04](p2-dash-host.md) and [P2-D05](p2-dash-fleet.md).
- Failures retry with backoff and surface through the failed-jobs indicator ([P1-O02](p1-operability.md)).
- Delivered as `AdvisoryFeedRefreshJob` and `Advisories::Feed`, every 6 hours in production (`cmdb/config/recurring.yml`), and `bin/rails advisories:refresh`.
  - **Source.** The default is OSV's `https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip`. OSV publishes no per-release archive, so this covers every Debian release and the importer keeps `Debian:13`. Set `FLEET_ADVISORY_FEED_URL` empty to turn the refresh off.
  - **Download.** HTTPS only, with the certificate verified (`VERIFY_PEER`). At most 3 HTTPS redirects, at most `FLEET_ADVISORY_MAX_DOWNLOAD_MB`, and within 15 minutes. Requests are conditional (`If-None-Match`, `If-Modified-Since`); a 304 is recorded as a successful refresh that imports nothing and is not audited. The import is full.
  - **Token.** An optional bearer token comes from `FLEET_ADVISORY_FEED_TOKEN` or credentials (`advisories.feed_token`) and is sent only to the configured host. Errors, logs, and stored sources name only the feed's host and path, never the query or the token.
  - **Failures.** Any failure is retried 5 times with backoff. After the last attempt it is recorded as a failed import, audited (`advisory.import_failed`), and raised, so it shows on the failed-jobs banner and page and in `/health`.
  - **Freshness.** `Advisories::Freshness` dates each ecosystem by its last successful full import. The fleet page shows "Advisory data last updated", or a warning when the data is older than `FLEET_ADVISORY_MAX_AGE_HOURS` (48) or was never refreshed. The warning reuses the existing notice style, since there is no Phase 2 mockup yet. The same indicator on [P2-D04](p2-dash-host.md) and [P2-D05](p2-dash-fleet.md) is built with those views.

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
