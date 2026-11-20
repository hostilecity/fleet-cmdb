# VT-SIGNALS: Import exploitation signals (CISA KEV and FIRST EPSS) and parse CVSS vectors

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (approved by the owner, 2026-11-19); decided in [ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md). The sources, their terms, sizes, and update times are in the epic, VT-M2.

## VT-S02: CISA KEV import

### Scope

- `FLEET_KEV_URL`, default `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` (CISA's GitHub mirror, CC0, synced shortly after cisa.gov); the alternative is CISA's own `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, whose front has refused automated clients (as the review reports). Empty stops the refresh and keeps the last data. Fetched every 6 hours after the advisory refresh with `Advisories::Feed` (HTTPS, certificate verified, conditional request, 15-minute limit, retries), limit `FLEET_KEV_MAX_DOWNLOAD_MB` (16), no redirects to another host. `bin/rails signals:kev_refresh` and `signals:kev_import FILE=...` for a server without internet access.
- Table `kev_entries`: CVE id (pattern-checked), date added, due date, known ransomware use (known or unknown), vendor and product (text, capped and sanitised); replaced in one transaction. The catalog version and count are kept on the import record. Other fields are not stored.
- Guard: an import that would drop more than `FLEET_ADVISORY_WITHDRAW_SHARE` (10%) of stored entries is held back with its counts, as P2-S16's guard; `ALLOW_DROPS=<count>` is a ceiling.
- After an import, the CVEs added or removed are handed to the triage run at once (VT-S05). An entry never opens, resolves, or reopens a finding or changes its severity.
- **Stale or stopped** (B1): the stored entries keep being used by rule N1 whatever their age; nothing is rewritten when the source goes stale. Staleness is shown at read time ("not re-checked against KEV since ..."). Stored entries are deleted only by `bin/rails signals:kev_clear`, which is audited and says that rules N1 and I5 stop applying.
- Audit `signal.kev_imported`, `signal.kev_import_failed`, `signal.kev_import_held_back`; freshness like P2-S16 with `FLEET_SIGNAL_MAX_AGE_HOURS` (168).

### Acceptance criteria

- [ ] A KEV file adds and removes entries in one transaction, and a file missing most entries is held back with its counts
- [ ] With the source off, failing, or stale, the data sources page and the freshness line say so, and advisory refreshes and matching are unaffected

## VT-S03: FIRST EPSS import

### Scope

- `FLEET_EPSS_URL`, default `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`; empty stops the refresh and keeps the last data. The URL redirects: up to 3 HTTPS redirects are followed, only to hosts in `FLEET_EPSS_REDIRECT_HOSTS`, and the build records the current target host in `docs/operations/configuration.md`, "Outbound access", so an allowlisted egress is configured with both (N1). Daily at 14:30 UTC (scores are published shortly after 13:30 UTC). `signals:epss_refresh` and `signals:epss_import FILE=...`.
- Streamed gzip CSV: the first line is a comment with the model version and score date, kept on the import; then `cve,epss,percentile`. Limits: 64 MiB compressed, 512 MiB uncompressed, 2 million rows. Rows with a malformed CVE or a number outside 0 to 1 are skipped and counted.
- Only CVEs named by stored advisories (ids and aliases) are kept, in `epss_scores` (CVE, score, percentile, band, score date). Band is `high` at a score of at least `FLEET_EPSS_ENTER` (0.10) and stays `high` until below `FLEET_EPSS_LEAVE` (0.07), so a score near the line does not move findings every day.
- A file older than the stored score date is refused. Guard as VT-S02 against a file with far fewer rows. CVEs whose band changed go to the next daily triage run (coalesced, VT-S05).
- Stale or stopped: the stored bands keep being used by rule N2 (B1). A CVE with no score has no band; N2 does not fire for it and its reason says "no EPSS score yet". Rule I5 does not depend on EPSS (S3).
- Attribution on the data sources page: "See EPSS at https://www.first.org/epss" (FIRST's usage terms).

### Acceptance criteria

- [ ] A score crossing 0.10 sets the band high and one falling to 0.08 keeps it high; below 0.07 it returns to normal
- [ ] An import of a real-sized file (about 300,000 rows) keeps only the fleet's CVEs, in bounded memory measured and recorded next to the limits

## VT-S04: CVSS vector parts on advisories

### Scope

- `advisories.cvss_av` (N, A, L, P), `cvss_pr` (N, L, H), `cvss_ui` (N, R), parsed from the CVSS v3 vector the severity rule already uses (`Advisories::Severity`); null when there is none. Set at import; an advisory whose vector changes is handed to the triage run.
- A one-off backfill from `severity_raw` for advisories already stored (or a full re-import; no backward compatibility is needed, NFR-5).

### Acceptance criteria

- [ ] `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` stores N, N, N and is shown as "network, no login, no user action"; a v2 or v4 vector stores nulls

## VT-D03: Data sources panels

### Scope

- Two panels on the Data sources page as drawn in [data-sources.html](../../mockups/vuln-triage/data-sources.html): freshness, entries kept and how many match open findings, the source's host and path, latest imports, the held-back state, and the offline task. They refresh with the advisory feed's "Refresh now" under its cool-down (P2-S15).
- The freshness line on host and fleet pages names KEV and EPSS.

### Acceptance criteria

- [ ] Both panels render the up-to-date, stale, off, and held-back states as drawn
- [ ] Every value from a feed is escaped, and only the source's host and path are shown
