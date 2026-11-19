# VT-EPIC: Vulnerability triage, risk exposure, and remediation progress (proposal)

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

**Status: proposed.** Nothing here is built. The owner approves the mockups (VT-D01), [ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md), the new requirement [FR-2.6](../../requirements.md#fr-26-vulnerability-triage-and-risk-exposure-proposed), and the answers to the open questions at the end before any slice starts.

## Why

The owner, in their words: "I don't need to remediate the findings, but I would like to represent to the user **what is fixable** vs **what is not fixable but still exploitable and may need additional compensating controls** vs **what can be safely ignored** ... sort of gamify the remediation and, at a glance, show which assets have the most work needed or have the worst security risk exposure."

A Debian 13 host typically shows thousands of open findings, and most have no fix for the release. `apt upgrade` barely moves the number. Three facts explain it:

- **The kernel dominates.** The Linux kernel became its own CVE numbering authority and assigns a CVE to most bug fixes: 3,529 kernel CVEs in 2024 and about 8 a day in early 2025 ([TuxCare](https://tuxcare.com/blog/the-linux-kernel-cve-flood-continues-unabated-in-2025-2/)). Matching is by source package (ADR 0011), so every kernel CVE is a finding on each binary package built from `linux`: the running image, every older image still installed, `linux-libc-dev`, and the headers.
- **Debian fixes in stable only what is worth a stable update.** Out-of-band DSAs for important issues, point releases for low-severity ones, and "some issues are simply not worth fixing in a stable release" ([Debian security team, triage](https://security-team.debian.org/triage.html)). Those stay open findings for the life of the release.
- **A count is not a risk.** CVSS "measures the severity of a vulnerability and ... must not be used as the only tool to assess risk" ([INCIBE on CVSS 3.1](https://www.incibe.es/en/incibe-cert/blog/measuring-severity-vulnerabilities-changes-cvss-31)).

So the dashboard should sort findings by what an operator can do about them, say why for each one, and measure progress in work done rather than in a raw count.

## What exists today

- Findings are per host, advisory, and binary package; state open, resolved, or reopened (P2-S11). An open finding's fixed version is the chunk verdict's (`chunk_matches.fixed_version`, ADR 0028), not a column of `vulnerability_findings`; `last_fixed_version` is written when an open finding's fix moves (ADR 0028, "As built", item 6).
- #253 (merged) groups a host's findings by package, worst first, with "Fix for N of M" ([P2-D04](p2-dash-host.md#p2-d04-host-vulnerabilities-view)). "Fixable" there means the advisory names a fixed version for the host's release.
- #252 (open) proposes a fix-available filter. This proposal **folds it in**: its definition and filter become the Fix available bucket, built first in [VT-FIXABLE](vt-fixable.md). Its questions are answered here or carried over (question 18).
- Debian's triage is imported per release, source package, and CVE: status, urgency (including `unimportant` and `end-of-life`), fixed version, no-DSA note and reason, and scope (local or remote) ([P2-S16](p2-debian-triage.md#p2-s16-import-the-debian-security-tracker-data)). DEC-22: it never changes a finding's state, severity, or any count.
- Advisories keep their raw severity, which is the CVSS v3 vector when there is one (`advisories.severity_raw`, [P2-S10](p2-vulns.md#p2-s10-advisory-model-and-osv-import)).
- The agent reports the running kernel (`kernel_version`, from `/proc/sys/kernel/osrelease`), running and enabled services (`services.running`, `services.enabled`), and every installed package with its source. It does not report listening sockets, which process uses which package, or a pending reboot. The `apply_package_updates` task already detects a pending reboot and services running old code, but only when it runs.
- Fleet pages read per-host summaries kept by database triggers (ADR 0026). There is no fleet-wide vulnerabilities page.
- No exploitation data (CISA KEV, FIRST EPSS) is imported.

## VT-M1: The triage model

Every open or reopened finding is in **exactly one bucket**, decided by the first rule below that matches, and carries that rule's id and a sentence the operator can read. The bucket never changes the finding's state, its severity, or the open count; it is a fourth attribute beside them ([ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md)). Resolved findings have no bucket.

| Bucket | Means | What to do |
|---|---|---|
| **Fix available** | The distribution has published a fixed version for this release. | Apply updates (and reboot for the kernel). |
| **Needs attention** | No fix for this release, and there is evidence it can be exploited here: known exploited, likely to be exploited, unsupported, or reachable over the network without credentials. | Consider a compensating control, accept the risk for a time, or replace the package. |
| **Low risk** | No fix, and no such evidence: local only, needs privileges or a user's action, a minor issue in the distribution's judgment, or idle on this host; or an operator recorded a control or accepted the risk. | Watch. It moves by itself if evidence appears. |
| **Ignorable** | The distribution or the host's own state says it does not apply here. | Nothing (or tidy up, such as removing an old kernel). |

The names are question 1. "Ignorable" is recommended over "Safe to ignore": the evidence behind it ("thought to be unexploitable or ineffective in most situations") does not support the word "safe".

### Rules, in order

| # | Id | Bucket | Condition | Reason shown (example) |
|---|---|---|---|---|
| 1 | I1 | Ignorable | The package is a kernel image (by the distribution's applicability table, VT-S05) whose kernel release is not the running one (`kernel_version`), and the running one is known. | "An older kernel, linux-image-6.12.38+deb13-amd64, is installed but not running (running: 6.12.48+deb13-amd64)." |
| 2 | I2 | Ignorable | The package is one the applicability table lists as holding no runtime code of its source (Debian: `linux-libc-dev`, `linux-headers-*`, `linux-kbuild-*`, `linux-compiler-*`, `linux-doc*`, `linux-source-*`, `linux-support-*`). | "linux-libc-dev holds kernel header files, not kernel code." |
| 3 | F1 | Fix available | The verdict has a fixed version for the host's release (the definition of #253 and #252). | "Debian fixed it in 3.5.1-1+deb13u2; this host has 3.5.1-1." |
| 4 | I3 | Ignorable | The tracker marks the CVE resolved for the release with no fixed version or `0`, which is how the tracker records "not affected". | "Debian says trixie is not affected." |
| 5 | I4 | Ignorable | The tracker marks it resolved for the release with a fixed version that the installed version is not older than (dpkg order). The advisory data lags the tracker. | "Debian marks it fixed in X; this host has Y." |
| 6 | O1, O2 | Low risk | An operator decision is active and not suspended ([VT-OVERRIDES](vt-overrides.md)): O1 control in place, O2 risk accepted. | "Control in place, recorded by ... until ...: '...'. Without it: Needs attention (N4)." |
| 7 | N1 | Needs attention | A CVE of the advisory is on CISA's KEV list. | "On CISA's Known Exploited Vulnerabilities list since 2026-11-02." |
| 8 | N2 | Needs attention | A CVE of the advisory has an EPSS band of "high": score at least 0.10, staying high until it falls below 0.07 (question 5). | "FIRST estimates a 31% chance of exploitation activity in the next 30 days." |
| 9 | I5 | Ignorable | The tracker's urgency for the release is `unimportant`, and the KEV and EPSS data are both current. | "Debian rates it unimportant: thought to be unexploitable or ineffective in most situations." |
| 10 | N3 | Needs attention | The tracker's urgency for the release is `end-of-life`: the package has no security support in this release. | "Debian gives no security support for this package in trixie, so no fix will come." |
| 11 | N4 | Needs attention | Severity medium or higher, and either the CVSS vector says network, no privileges, no user interaction (`AV:N/PR:N/UI:N`), or there is no vector and the tracker's scope is remote; and the agent does not report the package idle. | "Reachable over the network with no login and no user action, and smbd is listening on a network address." |
| 12 | L1 | Low risk | The agent's in-use report says no process uses the package and nothing of it listens. | "Installed but not used by any running process and not listening." |
| 13 | L2 | Low risk | Attack vector local or physical, or no vector and the tracker's scope is local. | "Needs local access: an attacker must already run code on this host." |
| 14 | L3 | Low risk | Network or adjacent vector that needs privileges (`PR:L`, `PR:H`) or a user's action (`UI:R`). | "Needs a logged-in attacker or a user to open something." |
| 15 | L4 | Low risk | The tracker has a no-DSA note for the release (no reason, postponed, or ignored). | "Debian judged it a minor issue and plans no security update for trixie." |
| 16 | L5 | Low risk | Anything else. | "Low severity, with no exploitation signal." When KEV or EPSS data is stale: "... not checked against KEV (data 9 days old)." |

Why this order:

- **Applicability first (I1, I2).** A flaw in a kernel that is not running, or in header files, is not exposure, whatever else is true. A KEV mark is still shown on such a finding.
- **Fix second (F1).** If an update clears it, that is the cheapest action, and a fix ends any operator decision (VT-OVERRIDES).
- **Distribution verdicts that the release is unaffected (I3, I4) before exploitation signals.** An exploit for code the release does not ship does not apply.
- **Operator decisions (O) before exploitation signals, but suspended by new ones.** A decision records the evidence it was made on; if a CVE is then added to KEV, crosses the EPSS threshold, or its severity rises, the decision is suspended and the finding falls through to N1 to N4.
- **Exploitation (N1, N2) before Debian's "unimportant" (I5).** Debian's own wording is "in most situations"; a KEV listing or a high EPSS is evidence that this is not most situations.
- **End of life (N3) is not ignorable.** The brief listed end-of-life under "safely ignored". In the tracker, `end-of-life` is an urgency meaning the package is not security supported in the release ([LTS team, CVE triage](https://lts-team.pages.debian.net/cve-triage.html): "when the package is not supported"). No fix will ever come, which is a reason to act, not to ignore (question 2).
- **"Ignored" and "postponed" are not ignorable either.** `<ignored>` means "a valid/strong reason not to fix it" and `<postponed>` "a minor issue ... that may be fixed later" (same source; [Debian security team](https://security-team.debian.org/triage.html): "some packages should rather not be fixed at all"). Neither says the flaw cannot be exploited, so they are L4 (Low risk), and N1 or N2 override them (question 4). The tracker itself hides no-DSA, ignored, and postponed entries unless asked ("include issues tagged <no-dsa>" and so on, [tracker release view](https://security-tracker.debian.org/tracker/status/release/testing)), which matches Low risk rather than Ignorable.
- **Network exposure without agent data fails toward attention (N4).** Until the agent reports what is idle, a network-reachable, unauthenticated flaw in an installed package is Needs attention (question 7).

**Missing data never makes a finding look safer.** Stale or turned-off KEV or EPSS data disables I5 (those findings become L5 with "not checked") and N1 or N2 cannot fire; the freshness line and the data sources page say so. No tracker entry disables I3, I4, I5, N3, and L4. No in-use report disables L1 and keeps N4. No running kernel disables I1.

### Debian Security Tracker states and where they land

| Tracker state for the host's release | Bucket | Source of the meaning |
|---|---|---|
| Resolved, fixed version newer than installed | F1 if the advisory names the fix; otherwise L5 with the tracker's fixed version shown (the data lags) | [P2-D08](p2-debian-triage.md#p2-d08-show-the-triage-in-the-dashboard) wording |
| Resolved, fixed version not newer than installed | I4 | as above |
| Resolved with no version or `0` ("not affected") | I3 | LTS team: "not-affected ... when [the] version is not affected" |
| Open, urgency `unimportant` | I5, unless N1 or N2 | Tracker: "considered unimportant from a security perspective ... thought to be unexploitable or uneffective in most situations" ([status/unimportant](https://security-tracker.debian.org/tracker/status/unimportant)) |
| Open, urgency `end-of-life` | N3 | LTS team: "when the package is not supported" |
| Open, no-DSA (none, postponed, ignored) | L4, unless N1, N2, or N4 | Debian security team triage; LTS team |
| Open, urgency low, medium, high, or not yet assigned | by N1 to L5 | |
| Undetermined, or no entry | by N1 to L5, without I3 to I5, N3, or L4 | |

## VT-M2: Exploitation and exposure signals

| Signal | What it is | Licence and terms | Update and size | How it is fetched |
|---|---|---|---|---|
| **CISA KEV** | "The authoritative source of vulnerabilities that have been exploited in the wild" ([cisa.gov/kev](https://www.cisa.gov/kev)); each entry has a CVE, date added, due date, required action, and "Known To Be Used in Ransomware Campaigns?". | CC0, public domain; the GitHub mirror says its licence is "identical to CISA's own KEV license" ([cisagov/kev-data](https://github.com/cisagov/kev-data)). | Updated when CISA adds entries, "usually shortly after cisa.gov, on weekdays during US Eastern business hours" ([kev-data README](https://raw.githubusercontent.com/cisagov/kev-data/main/README.md)). 1,748 entries in October 2026 ([Safeguard](https://safeguard.sh/resources/blog/cisa-kev-catalog-by-the-numbers-2026)): about 1 to 2 MB of JSON. | One JSON file (`known_exploited_vulnerabilities.json`, with a JSON schema) from CISA's feed or the GitHub mirror, every 6 hours with the advisory refresh, conditional request. Offline: a rake task imports the file. |
| **FIRST EPSS** | A daily probability (0 to 1) that a CVE sees exploitation activity in the next 30 days, and its percentile ([Safeguard on the CSV](https://www.safeguard.sh/resources/blog/epss-api-or-daily-csv-which-to-use)). It is not a severity. | "We grant the use of EPSS scores freely to the public"; attribution asked "where possible", for example "See EPSS at https://www.first.org/epss" ([EPSS usage agreement, mirrored](https://open.windriver.com/info/uni-license-list/licenses/first-epss-usage.html)). The data sources page carries that line. | Daily, "typically within a minute or two after 13:30 UTC" (Safeguard). Around 250,000 rows, growing about 30,000 a year, under 10 MB raw ([GitLab's EPSS ADR](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/epss/decisions/001_export_all_epss)). | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (redirects; the first line is a comment naming the model version and date), daily at 14:30 UTC. Only CVEs named by stored advisories are kept. The API is for lookups, not bulk, so it is not used. Offline: a rake task imports the file. |
| **CVSS v3 vector** | Already stored as the advisory's raw severity. `AV` is "network" when "the vulnerable system is bound to the network stack", local when it is not ([SSVC: CVSS attack vector](https://certcc.github.io/SSVC/reference/decision_points/cvss/attack_vector)); `PR` and `UI` say whether privileges or a user's action are needed. | Part of the OSV records already imported. | With the advisory data. | Parsed into columns on `advisories` at import: `cvss_av`, `cvss_pr`, `cvss_ui` (VT-S04). v2 and v4 vectors are not parsed (as today's severity rule). |
| **Debian scope** | Local or remote, per CVE, from the tracker (already stored). | Already imported (ADR 0022). | | Used only when there is no CVSS vector. |
| **In use on the host** | Whether a running process uses the package, and whether it listens on a network or loopback socket; the running kernel's build; a pending reboot ([VT-APPLICABILITY](vt-applicability.md)). | Reported by the agent; no third party. | With each package report. | Agent, read-only. |

The server fetches every feed; agents need no internet access and never contact these sources. Each new feed follows the existing pattern (P2-S13, P2-S16): HTTPS with the certificate verified, a download limit, a time limit, conditional requests, a guard against a truncated file (more than 10% of entries dropped is held back), freshness on the data sources page, failures on the failed-jobs page, an offline import task, and a URL setting that, when empty, turns the refresh off. New outbound destinations are an ADR 0032 decision and go in `docs/operations/configuration.md`, "Outbound access".

### How established tools present this, and what is taken

- **SSVC** (CERT/CC, CISA) decides with a few named decision points rather than a score: Exploitation (none, public PoC, active: "shared, observable, reliable evidence that the exploit is being used in the wild"), Exposure (small, controlled, open), Automatable, and impact ([SSVC overview](https://certcc.github.io/SSVC/ssvc_overview)); CISA's outcomes are Track, Track*, Attend, Act ([cisa.gov/ssvc](https://cisa.gov/ssvc)). **Taken:** the buckets are a small decision tree on named, inspectable points, and every outcome says which point decided it. N1 is SSVC's "active" exploitation; N4 is "open" exposure plus "automatable" (no privileges, no user action); Low risk is close to "Track".
- **Tenable VPR** is a proprietary 0.1 to 10 score from drivers such as exploit code maturity, threat intensity, and threat recency, and "Tenable does not customize these values for your organization" ([Tenable](https://docs.tenable.com/nessus/Content/RiskMetrics.htm)). **Not taken:** a machine-learned score cannot explain itself to an operator; the exposure score here is a published table.
- **Qualys TruRisk** sums severity-weighted detection scores per band, scaled by asset criticality, capped at 1,000 ([Qualys](https://docs.qualys.com/en/vmdr/latest/threat/calculating_asset_risk_score.htm)). **Taken:** a host score is a sum over findings weighted by severity band. **Not taken:** the detection score itself and the asset criticality factor (question 12 covers a per-host weight later).
- **Snyk's priority score** (0 to 1,000) adds factors for severity, exploit maturity, reachability, fixability, recency, and social trends, and "does not use the CVSS score alone" ([Snyk](https://docs.snyk.io/manage-issues/issue-management/priority-score)). **Taken:** fixability and exploit maturity as separate factors. **Not taken:** social trends and recency, which change a score without changing the risk.
- **Wiz**: "Installed-but-not-running findings drop in priority", "Internet-facing assets jump to the front of the queue", and KEV is a "high-confidence urgency signal" ([Wiz](https://www.wiz.io/academy/vulnerability-management/vulnerability-prioritization)). **Taken:** in use and listening (L1, N4), KEV first (N1).

## VT-M3: Exposure score and tier

**Points per open advisory on the host**, counted once per host in its worst bucket however many binary packages it matches:

| Bucket | Critical | High | Medium | Low or unknown |
|---|---|---|---|---|
| Needs attention | 40 | 20 | 8 | 2 |
| Fix available | 20 | 10 | 4 | 1 |
| Low risk | 2 | 1 | 0 | 0 |
| Ignorable | 0 | 0 | 0 | 0 |

A KEV-listed advisory scores double, except in Ignorable. The table is a constant in the code and the spec, the same for every host, and the host's tab shows the breakdown ("why 258 points", [tiles.html](../../mockups/vuln-triage/tiles.html#score)). Severity is the normalised severity (ADR 0011), never Debian's urgency.

**Tier**, the word shown with the score: **Known exploited** if any KEV advisory is in Needs attention or Fix available; else **Exposed, no fix** if any critical or high is in Needs attention; else **Fixes waiting** if any critical or high is in Fix available; else **Low** if any points; else **Minimal**. Not evaluated hosts have no score and no tier.

**Fleet:** no single fleet score (a sum grows with the fleet and means nothing). The fleet shows hosts per tier, the bucket totals, and the burn-down.

## VT-M4: Work remaining and progress

- **Work remaining** per host = distinct binary packages (name and architecture) with a Fix available finding, plus 1 when a reboot is pending (the running kernel's build is older than the installed image's version, or the agent reports the distribution's reboot flag). Needs attention advisories with no decision are listed beside it as decisions due, not as work, since there may be nothing to do.
- **Progress meter** per host, on the host tab only: of the findings that had a fix in the last 30 days, the share now resolved as `fixed` (resolved fixed in 30 days ÷ (that + Fix available now)). With nothing in either, it says "Nothing to install" instead of 100%. It never counts Low risk or Ignorable findings, so ignoring things cannot raise it.
- **Fleet burn-down**: Fix available and Needs attention per day for 90 days, with the share handled by a decision, and markers on days an import or a feed changed the numbers.

## VT-M5: Gamification, and the rules that keep it honest

What motivates: a meter that moves when work is done, a streak to keep, a short list of the most exposed hosts and the most work, and quick wins ("upgrade openssl: clears 162 findings on 8 hosts").

Honesty rules (acceptance criteria for VT-SCORES and VT-RISK-PAGE):

1. A badge states its exact claim and scope in its words ("No fixable critical for 12 days", "Nothing to install"), never "secure", "safe", "clean", "compliant", or "protected".
2. No badge, streak, or meter on a host that is not evaluated, or whose package report is older than 3 days, or when the data a badge depends on is stale; the place says "withheld" and why.
3. "Nothing to install" always shows the Needs attention count beside it when that is not zero.
4. Nothing rewards lowering Low risk or Ignorable counts. Removing old kernels is a "tidy-up" quick win that says it changes no exposure.
5. Streaks have a 7-day grace for a new fixable critical, so a new advisory does not break a run overnight; after that the run ends.
6. Rankings are of hosts and package upgrades, never of people. No operator points, levels, or leaderboards.
7. Jumps the operator did not cause (an advisory import, a feed change) are marked on the burn-down.
8. Accessibility: every bucket, tier, signal, and badge is a word plus a shape, never colour alone; meters are native `<meter>` with the numbers in text; charts are SVG with a title, a description, and a table of the numbers; nothing moves on its own; it works without JavaScript and under the app's CSP (no inline styles or scripts), as the mockups do.

## VT-M6: Computed where, and at a million hosts

| What | Where | Cost grows with |
|---|---|---|
| Fixed version of an open finding | Chunk verdict (exists) | distinct chunks (ADR 0028) |
| Bucket and rule id of each open finding | Two small columns on `vulnerability_findings`, written by the host's transitions whenever they differ, as the moved fix is written today | the host's findings, per host; a host whose buckets do not change writes nothing |
| Re-triage after a signal changes (KEV added, EPSS band changed, tracker entry changed, advisory vector changed) | A `TriageRun`, a new `EvaluationRun` kind: the advisories whose inputs changed, then their open findings by the existing `advisory_id` index, in host-id batches sized by lock time (as #204, #196) | hosts with those advisories; bounded by EPSS hysteresis and by updating only rows whose bucket changes |
| Re-triage after a host fact changes (kernel, in-use report, decision) | That host's transitions | one host |
| Per-host bucket counts, fix packages, KEV open, points, tier, decisions due, streak timestamps | New columns on `host_compliance_summaries`, recounted by the existing triggers when findings change (ADR 0026) | one host per changed host |
| Fleet bucket totals and hosts per tier | One sum over active summaries, like today's severity strip | the summaries table (narrow) |
| Fleet list and leaderboards sorted by points or work | Keyset pages on new summary indexes | constant per page |
| Burn-down | `vulnerability_daily_totals`, one row per day, bucket, and severity, written once a day from the summaries, kept 400 days | days |
| Quick wins | `vulnerability_quick_wins`, rebuilt after each matching or triage run and daily, from `chunk_matches` with a fix grouped by source package and fixed version, joined to sets and their hosts (ADR 0028's GIN index and `host_vulnerability_evaluations.package_set_id`). Approximate: it ignores host-specific rules and decisions, and says "as of" | distinct chunks and sets, not hosts times findings |
| Progress meter | Read on the host tab: resolved `fixed` in 30 days for that host | one host |

#252 noted that a trigger on findings alone cannot keep a "with a fix" count right, because the fix lives in the chunk verdict and an import can move it with no change of state. Its option (a) is taken: the bucket column on the finding is written by the matcher's transitions whenever the verdict's fix (or any other input) moves, so the summary triggers see it.

An advisory that every host has, added to KEV, re-triages every host's finding for it: about the cost ADR 0028 measured for an advisory's fan-out at a million hosts (about 20 minutes of one worker, spread over the evaluation workers), and the fleet counts are a few minutes behind meanwhile, as after an import today. Each slice measures its part with `bin/benchmark` before it is accepted.

## VT-D01: Mockups (delivered in the proposal PR)

Static HTML in [`docs/mockups/vuln-triage/`](../../mockups/vuln-triage/index.html), approved by the owner before any view is built (AGENTS.md):

- `index.html`: the screen list, the model, and the review questions.
- `host-vulns.html`: the host Vulnerabilities tab with the four buckets, reasons, work remaining, progress, and suggested controls.
- `fleet.html`: the fleet list with Exposure and Work columns.
- `risk-overview.html`: the new fleet Risk page: buckets, burn-down, most exposed, most work, quick wins, streaks, decisions due.
- `override.html`: recording a control or accepting a risk, with errors, the saved result and audit entry, and a suspended decision.
- `tiles.html`: the host summary tiles today and proposed, tile states, and the score explanation.
- `states.html`: stale or missing data, not evaluated hosts, and what a badge may say.
- `data-sources.html`: the KEV and EPSS panels.

### Acceptance criteria

- [ ] The owner has approved the mockups in the proposal PR
- [ ] Every bucket, rule family, signal, and honesty rule above is drawn somewhere, and no screen uses colour alone

## Slices, in build order

1. [VT-FIXABLE](vt-fixable.md): store whether each open finding has a fix, count it in the summaries, and filter by it (folds in #252).
2. [VT-SIGNALS](vt-signals.md): import CISA KEV and FIRST EPSS, and parse CVSS vectors.
3. [VT-APPLICABILITY](vt-applicability.md): the agent reports the running kernel's build, a pending reboot, and which packages are in use. Can run in parallel with 1 and 2.
4. [VT-BUCKETS](vt-buckets.md): the classifier, stored buckets, re-triage runs, and summary counts.
5. [VT-HOST-TAB](vt-host-tab.md): the host tab with buckets, reasons, work, progress, and controls.
6. [VT-OVERRIDES](vt-overrides.md): operator decisions with expiry, audit, and suspension.
7. [VT-SCORES](vt-scores.md): exposure score and work on the summaries, the fleet list, and the tiles.
8. [VT-RISK-PAGE](vt-risk-page.md): the fleet Risk page with burn-down, leaderboards, quick wins, and streaks.

## Acceptance criteria (the whole proposal)

- [ ] Every open finding on an evaluated host is in exactly one bucket with a rule id and a readable reason, and the four bucket counts add up to the open count on the host tab, the fleet list, and the Risk page
- [ ] No finding is Ignorable or Low risk because data is missing or stale, and no badge implies a host is safe
- [ ] Fleet pages cost the same per page at a million hosts as at 50 (measured with `bin/benchmark`), and nothing is computed per host times findings on a page view

## Open questions for the owner

Each has a recommended default. A reply such as "1 yes, 2 yes, 5 0.05 ..." is enough.

1. **Bucket names.** "Fix available", "Needs attention", "Low risk", "Ignorable" (recommended), or "Safe to ignore" for the last? Recommended: "Ignorable", since Debian's own wording is "in most situations".
2. **Debian end-of-life.** Put `end-of-life` in Needs attention (rule N3), not in Ignorable as the brief suggested? Recommended: yes; it means no security support, so no fix will come.
3. **Debian unimportant.** Ignorable (rule I5) unless KEV-listed or EPSS high, and only while those feeds are current? Recommended: yes.
4. **No-DSA, postponed, ignored.** Low risk (rule L4) unless an exploitation or exposure rule matches first? Recommended: yes.
5. **EPSS threshold.** Enter Needs attention at a probability of 0.10 and leave below 0.07? Alternatives: a percentile (for example the top 5%), or a lower 0.05. Recommended: 0.10 / 0.07, as a setting.
6. **New outbound sources.** Fetch KEV (CISA's feed, GitHub mirror as an alternative URL) and EPSS (FIRST's daily CSV) by default, each with a URL setting that turns it off and an offline import task? Recommended: yes, on by default (ADR 0032).
7. **Network exposure before the agent reports use.** Keep unauthenticated, network-reachable findings of medium or higher in Needs attention (rule N4) on hosts whose agent does not report what is idle? Recommended: yes (fail toward attention); it relaxes by itself once VT-APPLICABILITY ships.
8. **Kernels.** Old kernel images that are not running, and `linux-libc-dev` and the headers, are Ignorable (rules I1, I2), with "remove old kernels" offered as a tidy-up? Recommended: yes.
9. **In-use detection needs a privilege.** Reading which process maps which library and owns which socket (`/proc/<pid>/maps`, `/proc/<pid>/fd`) needs ptrace read access to other users' processes, which the agent's unit does not grant today (its capability bounding set is `CAP_DAC_READ_SEARCH` only). Options: (a) add `CAP_SYS_PTRACE` to the bounding set, read-only use only; (b) report only what needs no new privilege: running services' executables and their packages, the running kernel's build, and the reboot flag; (c) (b) by default, (a) when the VM's local config enables it. Recommended: (c). Rule L1 then applies only on hosts that enable it.
10. **Second factor for decisions.** Require the TOTP step-up to record a decision? Recommended: no, since a decision changes no host; it is audited, expires, never hides a finding from the open count, and is suspended by new evidence. Ask for the step-up when one action records decisions on more than 10 hosts.
11. **Decision limits.** Who and how long: any operator; reason required (10 to 1,000 characters); at most 90 days, 30 for a KEV-listed finding; only on Needs attention and Low risk findings (a fix ends a decision). Recommended: as written.
12. **Score.** The published points table, each advisory once per host, KEV doubled (recommended), or no number and only the tier with a lexicographic sort as #253 does? A per-host weight (asset criticality, as Qualys has) later, not now. Recommended: the table, no weight.
13. **Work unit.** Package upgrades plus one for a pending reboot (recommended), or findings?
14. **Order of the host tab's sections.** Fix available first, then Needs attention (recommended, since it is the work you can do), or Needs attention first?
15. **Fleet list.** Replace the "Open vulnerabilities" column with sortable "Exposure" and "Work" columns, the open count staying on the host tab and Compliance? Recommended: yes.
16. **A Risk page.** A new top-level page "Risk" after Compliance (recommended), or these panels on the Compliance page?
17. **Milestone.** A separate milestone, built after Phase 2 acceptance and not gating Phase 3 acceptance? Recommended: yes ("Vulnerability triage (proposed)" in `config.yml`).
18. **#252.** Fold it into VT-FIXABLE and close it when this proposal is approved, with its answers taken from here: Q1 "Fix available"; Q2 yes; Q3 not now; Q4 replaced by the bucket line and fleet columns (question 15); Q5 replaced by the Risk page; Q6 yes; Q7 yes; Q8 a bucket filter combines with a severity filter as "a finding in this bucket of this severity"; Q9 yes, host tab only; Q10 the tab shows every bucket; Q11 no, the buckets use triage instead and say so; Q12 keep severity first inside each bucket. Recommended: yes.
19. **Suggested controls.** A short table in the repository keyed by rule and attack vector (for example network service, crafted file, local privilege escalation, unsupported package), shown under Needs attention as advice only, with no third-party content? Recommended: yes.
20. **Burn-down history.** Keep the daily totals 400 days (a few thousand small rows)? Recommended: yes.
