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
  - **Dashboard uploads** ([P2-D06](p2-dash-fleet.md)) use the same importer in a background job: `advisory_imports` rows can be `queued` and `importing` (with no `finished_at`) before they succeed or fail, and `advisory_uploads` holds the file until the job has read it.
  - **Ecosystems.** `Ecosystems` (`cmdb/app/models/ecosystems.rb`) is the fleet-profile table, built here because the importer keeps only its ecosystems: `debian` `13` → `Debian:13`. Records for other ecosystems are skipped.
  - **Transactions and limits.** One transaction per import, under an advisory lock. Each document is read to at most 2 MiB; an archive may be at most 512 MiB (`FLEET_ADVISORY_MAX_DOWNLOAD_MB`), a million documents, and 8 GiB of JSON read, which counts refused entries too. A record whose shape the parser did not expect is reported as malformed rather than rolling back the import.
  - **Stored values.** Text has control characters removed and a length cap; summaries are at most 512 characters. Ids, package names, and range versions are pattern-checked; whether dpkg can parse a version is left to matching.
  - **Severity rule.** A CVSS v3 base score (computed from the vector, banded as CVSS bands it), then `database_specific.severity`, then a Debian urgency, else unknown. The raw value is kept. v2 and v4 vectors are kept as raw but not scored.
  - **Withdrawn and absent advisories.** Withdrawn advisories are kept and marked. A full import (the refresh, or `FULL=1`) also marks advisories it does not contain as withdrawn (`absent`), because OSV moves withdrawn records out of an ecosystem's archive, so the archive alone would never withdraw anything. This was added beyond the original scope. The sweep is skipped when any record was malformed. It only touches advisories no newer than the newest record in the import, so an older archive, or an older download imported after a newer one, cannot withdraw advisories it never knew about.
  - **Re-matching.** The import returns the packages that changed advisories name, before and after. Once it commits, `VulnerabilityMatchJob` re-matches those packages ([P2-S11](#p2-s11-vulnerability-matching-job-and-finding-lifecycle)).
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
- A manual refresh from the dashboard has a cool-down: [P2-S15](p2-refresh-limit.md).
- Delivered as `AdvisoryFeedRefreshJob` and `Advisories::Feed`, every 6 hours in production (`cmdb/config/recurring.yml`), and `bin/rails advisories:refresh`.
  - **Source.** The default is OSV's `https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip`. OSV publishes no per-release archive, so this covers every Debian release and the importer keeps `Debian:13`. Set `FLEET_ADVISORY_FEED_URL` empty to turn the refresh off.
  - **Download.** HTTPS only, with the certificate verified (`VERIFY_PEER`). At most 3 HTTPS redirects, at most `FLEET_ADVISORY_MAX_DOWNLOAD_MB`, and within 15 minutes for the whole exchange (`Timeout`), including the status line and headers. Requests are conditional (`If-None-Match`, `If-Modified-Since`), unless the last download had malformed records, in which case the archive is fetched in full again. A 304 is recorded as a successful refresh that imports nothing and is not audited. The import is full.
  - **Token.** An optional bearer token comes from `FLEET_ADVISORY_FEED_TOKEN` or credentials (`advisories.feed_token`) and is sent only to the configured host. Errors, logs, and stored sources name only the feed's host and path, never the query or the token.
  - **Failures.** Any failure is retried 5 times with backoff. After the last attempt it is recorded as a failed import, audited (`advisory.import_failed`), and raised, so it shows on the failed-jobs banner and page and in `/health`. `bin/rails advisories:refresh` makes one attempt and records and audits a failure the same way.
  - **Freshness.** `Advisories::Freshness` dates each ecosystem by its last successful full import. The fleet page shows "Advisory data last updated", or a warning when the data is older than `FLEET_ADVISORY_MAX_AGE_HOURS` (48) or was never refreshed. The warning reuses the existing notice style, since there is no Phase 2 mockup yet. The same indicator on [P2-D04](p2-dash-host.md) and [P2-D05](p2-dash-fleet.md) is built with those views.

### Acceptance criteria

- [ ] A failed or timed-out fetch retries and is visible to an operator
- [ ] The freshness warning appears when data is older than the threshold
- [ ] No secret appears in logs or error messages

## P2-S11: Vulnerability matching job and finding lifecycle

### Scope

- A host-to-ecosystem mapping from the inventory's distribution id and release (table maintained with the [DEC-01](../../decisions/0001-fleet-profile.md) fleet profile). Hosts with no mapping or no advisory data show "not evaluated" with the reason.
- Matching on source package name within the host's ecosystem, comparing the installed version to affected ranges with the manager's comparator ([P2-S09](p2-packages.md)). One finding per host, package, and advisory.
- Finding states: `open`, `resolved` (installed version outside every affected range, whether the package was updated or the advisory's ranges changed; package removed; or advisory withdrawn), and `reopened` (condition returns). Timestamps for first seen, resolved, and reopened.
- Decision (skipped packages, [P2-S08](p2-packages.md)): a package the agent reports as skipped (an interrupted installation) is not installed as far as matching goes, so its findings resolve as `removed` and reopen when the package is listed again. The matcher does not read the skipped names. A host whose package database was unreadable is not evaluated and its findings stay as they were.
- Runs in a background job triggered by a new package snapshot (that host only) and by advisory imports (affected packages only). Idempotent.
- Efficient for 50 hosts by 2,000 packages: indexed lookups by ecosystem and package, no per-package queries in loops.
- Delivered as `VulnerabilityMatcher` (`cmdb/app/services/vulnerability_matcher.rb`, ranges in `vulnerability_matcher/ranges.rb`), `HostContext`, and `VulnerabilityMatchJob`, with the tables `vulnerability_findings` and `host_vulnerability_evaluations` (`cmdb/README.md`, "Vulnerability findings").
  - **Ecosystem mapping.** `Ecosystems` (from [P2-S10](#p2-s10-advisory-model-and-osv-import)) maps the inventory's os id and version to an ecosystem.
  - **Ranges.** OSV's evaluation algorithm over `ECOSYSTEM` ranges: `introduced`, `fixed`, `last_affected`, `limit` (an exclusive upper bound on the range), and `introduced: "0"` for all versions. A finding's fixed version is the fix of the range the installed version is in, or none when that range has no fix. Versions are compared with `PackageVersions` (dpkg), never as strings.
  - **Not evaluated.** A host is not evaluated, with a reason and a sentence, when it has no inventory, is on a distribution outside the fleet profile, has no package report, has an unsupported manager, or its ecosystem has no advisory data. Its findings are then left unchanged. A version dpkg cannot parse, installed or in a range, leaves that package and advisory not evaluated: it is listed (at most 100, all counted) and its finding is unchanged.
  - **Finding states.** Resolutions are `fixed`, `removed`, `withdrawn`, and `not_affected` (the advisory stopped naming the package). `resolved_at` keeps the last resolution after a reopen. An advisory withdrawn by an update that lists no packages still resolves its findings as `withdrawn`.
  - **When matching runs.** After commit, for the host, when `PackageRecorder` writes a new snapshot. After an import, for the hosts with a package from a changed source package or a finding for one, for those packages only. In full, for hosts never evaluated or evaluated as "no advisory data" (chosen before the targeted run), and for a host whose not-evaluated list was cut short, so its count stays exact. A targeted run starts findings only for its own source packages. On demand: `bin/rails vulnerabilities:match`.
  - **Concurrency.** Each host is matched in its own short transaction holding its row lock (`FOR UPDATE`, as every package report and heartbeat takes it), so matching never sees half of a report, and an agent waits for at most one host's matching. Advisories are loaded once per call for every source package the hosts have. Per host there is a fixed number of queries whatever its package count, and writes are batched upserts.
- Decision (binary packages): one finding per host, advisory, and installed binary package (name and architecture). Binary packages built from one source each get their own finding, because each is installed, updated, and removed on its own, and the operator acts on what dpkg lists. Multi-arch copies (`libssl3t64:amd64` and `:i386`) are separate findings. Dashboards may group them by source.
- Time budget: 20 s for 50 hosts by 2,000 packages. Measured (`spec/services/vulnerability_matcher_performance_spec.rb`, sandbox, PostgreSQL on the same machine), with 600 advisories over 300 source packages and 20,000 findings opened: 5.0 s and 354 queries (about 7 per host). Matching again, with nothing changing, takes 2.5 s.

### Acceptance criteria

- [ ] AC-2.4: importing an advisory for an installed version creates an open finding; after the package is updated on the VM and re-reported, the finding resolves
- [ ] A downgrade or reinstall of a vulnerable version reopens the finding
- [ ] Binary packages built from the same source package yield one finding per binary package actually installed (decision recorded and tested)
- [ ] Matching 50 hosts completes within the time budget recorded in the PR
