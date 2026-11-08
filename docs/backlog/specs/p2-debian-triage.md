# P2-DEBIAN-TRIAGE: Debian's own triage beside each finding

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Added after Phase 2's dashboards (owner, 2026-11-07): CVE-2026-19499 shows High in the dashboard (its CVSS score) while Debian notes `<no-dsa> (Minor issue)` for trixie. Decided in [ADR 0022](../../decisions/0022-distribution-triage.md): import the Debian Security Tracker's JSON beside OSV and show Debian's triage next to each finding, without changing states, severity, or counts.

## P2-D07: Mockups for the triage display

Delivered first, as its own pull request (`Refs` the issue), and approved by the owner before any view is built ([AGENTS.md](../../../AGENTS.md)). Changes to the Phase 2 mockups in `docs/mockups/phase-2/`:

- `host-vulns.html`: each advisory row under a package shows Debian's triage for the host's release when there is one, e.g. "Debian: no security update planned" (no-DSA), "Debian: postponed to a later update or point release", "Debian: ignored, no fix planned for this release", "Debian: unimportant", the urgency when assigned, and "Debian triage not available" when the source is off, stale, or has no entry. Debian's own note text follows the category verbatim (escaped), up to 200 characters. A filter chip, "Debian: no security update planned", for findings whose entry has a no-DSA note of any reason: none, postponed, or ignored (owner, T3 on #134). Severity and counts are unchanged.
- `host-vuln-package.html`: the same per advisory, with a link to the tracker's page for the CVE and the CVE's scope (local or remote). Scope is shown on the package page only, and Debian's bug number is not shown (owner, T6 on #134).
- `data-sources.html`: a second source, "Debian Security Tracker", with its freshness, last import, entry counts per release, and its own stale and held-back states; no upload for it. It has no refresh button of its own: the advisory feed's "Refresh now" refreshes OSV and then the tracker, under the same cool-down (owner, T2 on #134).
- `index.html`: entries for the changed pages and the open design questions.

### Acceptance criteria

- [ ] The three pages show every triage state above, the "not available" state, and the stale source
- [ ] Wording never implies a finding is fixed or not affected because of Debian's triage

## P2-S16: Import the Debian Security Tracker data

### Scope

- A scheduled refresh (`FLEET_DEBIAN_TRACKER_URL`, default `https://security-tracker.debian.org/tracker/data/json`; empty turns it off) runs on the advisory schedule after the OSV refresh, over HTTPS with the certificate verified, with a conditional request (ETag or Last-Modified), a download limit, and a time limit. It is one document per refresh. The dashboard's "Refresh now" runs the OSV refresh and then this one, under the one manual-refresh cool-down (owner, T2 on #134); a tracker failure does not change the OSV refresh's outcome. `bin/rails advisories:triage_refresh` runs it now, and `bin/rails advisories:triage_import FILE=...` imports a file for a server without internet access.
- Parse within bounded memory and nesting (the document is keyed by source package, then CVE, then release). Measure the real file's size, entry count, and peak memory, and record them next to the limits, as for the OSV archive.
- Keep only the releases the fleet uses, through a mapping from the host's inventory (`ID`, `VERSION_ID`) to the tracker's release name (`debian`/`13` is `trixie`) held in one table, so adding a release is a data change. Nothing in the import assumes Debian 13.
- Store, per release, source package, and CVE: the status (resolved, open, undetermined), urgency, fixed version, the no-DSA note text with its reason (none, postponed, ignored), and whether a fix is planned for the next point release; and per CVE its scope (local or remote), which the package page shows (T6 on #134), replacing the previous data in one transaction per release. A malformed entry is skipped and counted, not fatal.
- Guard against a truncated or wrong file: an import that would drop more than 10% of a release's stored entries keeps the previous data, is recorded as held back with the counts (as the OSV withdrawal guard does, review of #131), and is shown on the data sources page. Triage never resolves or reopens a finding, so this protects only what the dashboard shows.
- Join a finding to triage by the finding's source package, the host's release, and the advisory's CVE identifiers (its id for `DEBIAN-CVE-*` records, its aliases and upstream ids for `DSA-*` and `DLA-*` records). Expose it for the views in one query per page, with no per-finding lookups.
- Freshness like OSV's: its own last success, a warning past `FLEET_ADVISORY_MAX_AGE_HOURS`, failures on the failed-jobs page. A failure never blocks OSV refreshes or matching.
- Audit every import with its outcome and counts. Retention keeps the current data and the import records as the OSV imports are kept.
- Document the setting in `docs/operations/configuration.md` and the outbound access to `security-tracker.debian.org`.

### Acceptance criteria

- [ ] For CVE-2026-19499 on a trixie host with glibc 2.41-12+deb13u4, the finding stays open with its OSV severity, and Debian's "no-DSA, minor issue" note is available for it
- [ ] An import of a file missing most of a release's entries keeps the previous data and is shown as held back with the counts
- [ ] With the source turned off, failing, or stale, findings say Debian's triage is not available, and OSV refreshes and matching are unaffected

## P2-D08: Show the triage in the dashboard

### Scope

- Build what the approved P2-D07 mockups show: triage beside each finding on the host's vulnerabilities tab and the package page, the "Debian: no security update planned" filter (no-DSA notes of any reason: none, postponed, or ignored), and the second source on the data sources page with its freshness and held-back state. The one "Refresh now" refreshes OSV and then the tracker under the same cool-down, and its confirmation says so.
- Show the CVE's scope (local or remote) on the package page only; do not show Debian's bug number (owner, T6 on #134).
- Escape every value from the tracker; link only to `https://security-tracker.debian.org/tracker/<CVE>` built from a validated CVE id.
- No change to the compliance page's counts or to severity filters.

### Acceptance criteria

- [ ] Every triage state, "not available", and the stale and held-back source states render as approved
- [ ] The host vulnerabilities tab stays within its query bound with triage shown (measure at a host with 500 findings)
