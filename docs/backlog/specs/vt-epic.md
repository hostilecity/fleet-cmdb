# VT-EPIC: Vulnerability triage, risk exposure, and remediation progress

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

**Status: approved by the owner on 2026-11-19** (epic #264; slices #256 to #263; PR #265). Nothing here is built yet. The decisions are recorded at the end, "Decided by the owner (2026-11-19)". Revised after the independent review of PR #265 (B1, B2, S1 to S12, N1 to N11) before approval.

## Why

The owner, in their words: "I don't need to remediate the findings, but I would like to represent to the user **what is fixable** vs **what is not fixable but still exploitable and may need additional compensating controls** vs **what can be safely ignored** ... sort of gamify the remediation and, at a glance, show which assets have the most work needed or have the worst security risk exposure."

A Debian 13 host typically shows thousands of open findings, and most have no fix for the release. `apt upgrade` barely moves the number. Three facts explain it:

- **The kernel dominates.** The Linux kernel became its own CVE numbering authority and assigns a CVE to most bug fixes: 3,529 kernel CVEs in 2024 and about 8 a day in early 2025 ([TuxCare](https://tuxcare.com/blog/the-linux-kernel-cve-flood-continues-unabated-in-2025-2/)). Matching is by source package (ADR 0011), so every kernel CVE is a finding on each binary package built from `linux`: the running image, every other image still installed, `linux-libc-dev`, and the headers.
- **Kernel fixes need a new package and a reboot.** In trixie each kernel update is a new binary package (`linux-image-6.12.57+deb13-amd64` beside `linux-image-6.12.48+deb13-amd64`), pulled in by the `linux-image-amd64` metapackage. `apt-get upgrade`, and the `apply_package_updates` task (`APT::Get::Upgrade-Allow-New=false`, DEC-16), never install a new package, so they never install a kernel fix (`apt upgrade` does, since it installs new packages a dependency needs; `apt full-upgrade` can also remove packages); an installed kernel fixes nothing until the host boots it, and the old versioned image keeps its findings until it is removed (`apt autoremove`). (Wording corrected in the review of #267, #256: the earlier text said `apt upgrade` never installs it. No decision changes.)
- **Debian fixes in stable only what is worth a stable update.** Out-of-band DSAs for important issues, point releases for low-severity ones, and "some issues are simply not worth fixing in a stable release" ([Debian security team, triage](https://security-team.debian.org/triage.html)). Those stay open findings for the life of the release.

And a count is not a risk: CVSS "measures the severity of a vulnerability and ... must not be used as the only tool to assess risk" ([INCIBE on CVSS 3.1](https://www.incibe.es/en/incibe-cert/blog/measuring-severity-vulnerabilities-changes-cvss-31)). So the dashboard should sort findings by what an operator can do about them, say why for each one, and measure progress in work done rather than in a raw count.

## What exists today

- Findings are per host, advisory, and binary package; state open, resolved, or reopened (P2-S11). An open finding's fixed version is the chunk verdict's (`chunk_matches.fixed_version`, ADR 0028), not a column of `vulnerability_findings`; `last_fixed_version` is written when an open finding's fix moves (ADR 0028, "As built", item 6). Resolution `fixed` means "the installed version is outside the affected ranges", which also happens when the advisory data changes.
- #253 (merged) groups a host's findings by package, worst first, with "Fix for N of M" ([P2-D04](p2-dash-host.md#p2-d04-host-vulnerabilities-view)).
- #252 proposed a fix-available filter. It is **folded into** [VT-FIXABLE](vt-fixable.md) by the owner's decision (decision 22) and is closed when PR #265 merges.
- Debian's triage is imported per release, source package, and CVE: status, urgency (including `unimportant` and `end-of-life`), fixed version, no-DSA note and reason, whether a fix is planned for the next point release, and scope ([P2-S16](p2-debian-triage.md#p2-s16-import-the-debian-security-tracker-data)). DEC-22: it never changes a finding's state, severity, or any count.
- Advisories keep their raw severity, which is the CVSS v3 vector when there is one (`advisories.severity_raw`, [P2-S10](p2-vulns.md#p2-s10-advisory-model-and-osv-import)).
- The agent reports the running kernel release (`kernel_version`), running and enabled services, and every installed package with its source, so the server already knows which kernel images are installed and which one is running. It does not report listening sockets, which process uses which package, or a pending reboot.
- Fleet pages read per-host summaries kept by database triggers (ADR 0026). There is no fleet-wide vulnerabilities page. No exploitation data (CISA KEV, FIRST EPSS) is imported.

## VT-M1: The triage model

Every open or reopened finding is in **exactly one bucket**, decided by the first rule below that matches, and carries that rule's id and a sentence the operator can read. The bucket never changes the finding's state, its severity, or the open count ([ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md)). Resolved findings have no bucket.

| Bucket | Means | What to do |
|---|---|---|
| **Fix available** | A fix for this release exists: a package upgrade, a newer kernel package, or a reboot into a kernel already installed. | Upgrade, install the new kernel, or reboot. |
| **Needs attention** | No fix for this release, and evidence it can be exploited here: known exploited, likely to be exploited, unsupported, or reachable over the network without credentials. Accepted risks stay here, marked. | Record a compensating control, accept the risk for a time, or replace the package. |
| **Low risk** | No fix, and no such evidence (local only, needs privileges or a user's action, a minor issue in Debian's judgment), or a compensating control is recorded. | Watch. It moves by itself if evidence appears. |
| **Ignorable** | Debian or the host's own state says it does not apply here. | Nothing, or tidy up (remove an old kernel). |

The owner asked for three categories; this has four, which the owner approved (decision 1). "Not fixable" splits into **Needs attention** and **Low risk** because on the example host 9 findings have exploitation evidence and 1,230 have none, and one list of 1,239 would bury the 9. Merging Low risk into Needs attention or into Ignorable were the rejected alternatives.

### Rules, in order

| # | Id | Bucket | Condition | Reason shown (example) |
|---|---|---|---|---|
| 1 | I1 | Ignorable | A kernel image (by the distribution's applicability table, VT-S05) that is installed but not the running kernel (`kernel_version`), when the running one is known. | "linux-image-6.12.57+deb13-amd64 is installed but not running yet (running: 6.12.48+deb13-amd64). It is triaged when the host boots it." |
| 2 | I2 | Ignorable | A package the applicability table lists as holding no runtime code of its source (Debian: `linux-libc-dev`, `linux-headers-*`, `linux-kbuild-*`, `linux-compiler-*`, `linux-doc*`, `linux-source-*`, `linux-support-*`). | "linux-libc-dev holds kernel header files, not kernel code." |
| 3 | K1 | Fix available | The running kernel image, with a fix (rule F1's or F2's version), and a newer image of the same flavour at or above that version is already installed. #274 (approved by the owner on 2026-11-23): of the same series (a backport counts only for a backport's fix, which may be Debian:14's; [vt-buckets.md](vt-buckets.md)). | "Fixed in 6.12.57+deb13, which is installed. Reboot into it." |
| 4 | K2 | Fix available | The running kernel image, with a fix, and no installed image is at or above it. | "Fixed in 6.12.57+deb13. Install the new kernel package (`apt full-upgrade`; the update task does not install new packages), then reboot." |
| 5 | F1 | Fix available | The verdict has a fixed version for the host's release (#252 and #253's definition). | "Debian fixed it in 3.5.1-1+deb13u2; this host has 3.5.1-1." |
| 6 | F2 | Fix available | No fixed version in the advisory data, but Debian's tracker marks it resolved for the release at a version newer than the installed one (the advisory data lags). | "Debian's tracker says it is fixed in X for trixie; the advisory data has not caught up. Upgrade to X." |
| 7 | I3 | Ignorable | The tracker marks the CVE resolved for the release with no fixed version or `0`, which is how the tracker records "not affected". | "Debian says trixie is not affected." |
| 8 | I4 | Ignorable | The tracker marks it resolved for the release at a version the installed version is not older than (dpkg order). | "Debian marks it fixed in X; this host has Y." |
| 9 | O1 | Low risk | An operator recorded a compensating control, not expired and not suspended ([VT-OVERRIDES](vt-overrides.md)). | "Control in place, recorded by ... until ...: '...'. Without it: Needs attention (N4)." |
| 10 | N1 | Needs attention | A CVE of the advisory is in the stored KEV catalog. | "On CISA's Known Exploited Vulnerabilities list since 2026-11-02." |
| 11 | N2 | Needs attention | A CVE of the advisory has a stored EPSS band of "high": a score of at least 0.10, staying high until it falls below 0.07 (decision 6). | "FIRST estimates a 31% chance of exploitation activity in the next 30 days." |
| 12 | I5 | Ignorable | The tracker's urgency for the release is `unimportant`, and KEV data has been imported at least once (rules N1 and N2, above, override it). | "Debian rates it unimportant: it does not affect the Debian binary packages, or is thought unexploitable in most situations." |
| 13 | N3 | Needs attention | The tracker's urgency for the release is `end-of-life`, or the package is `<removed>` from the release but still installed: no security support. | "Debian no longer supports this package in trixie, so no fix will come." |
| 14 | N4 | Needs attention | Severity medium or higher, and either the CVSS vector says network, no privileges, no user action, or there is no vector and the tracker's scope is remote (an `unknown` severity counts as medium, owner's OK in #277). | "Reachable over the network with no login and no user action." |
| 15 | N5 | Needs attention | A process holding a listening socket loads the package: the agent's library scan lists it in `loaded_by_listeners`, and the server received that scan less than 24 hours ago (decision 27; [VT-APPLICABILITY](vt-applicability.md)). So L2 to L5 cannot apply. | "Loaded by openssh-server (ssh.service on 0.0.0.0:22/tcp), which listens on the network, so it stays in Needs attention." (the unit and sockets only when the scan names them) |
| 16 | L2 | Low risk | Attack vector local or physical, or no vector and the tracker's scope is local. | "Needs local access: an attacker must already run code on this host." |
| 17 | L3 | Low risk | Network or adjacent vector that needs privileges or a user's action. | "Needs a logged-in attacker or a user to open something." |
| 18 | L4 | Low risk | The tracker has a no-DSA note for the release (no reason, postponed, or ignored). | "Debian judged it a minor issue and plans no security update for trixie; a fix is expected in the next point release." (the last part only when the tracker says so) |
| 19 | L5 | Low risk | Anything else. | "Low severity, with no exploitation signal." |

An **accepted risk** (O2) is not a rule: the finding stays in the bucket the rules give (normally Needs attention), with its points and tier, marked "risk accepted until ..." and left out of "decisions due" (S1).

Why this order:

- **Applicability first (I1, I2).** A flaw in a kernel that is not running, or in header files, is not exposure. A KEV mark is still shown. I1 also covers a newer kernel installed but not yet booted; its findings are triaged when it runs.
- **Kernel fixes are their own rules (K1, K2).** In trixie the running image can never be upgraded in place: its fix is another package. K1 says "reboot", K2 "install the new kernel, then reboot". After the reboot the old image's findings move to I1; the work counts as done (VT-M4).
- **Fix next (F1, F2).** The cheapest action. F2 uses Debian's own per-release fixed version when the advisory data lags; it never resolves a finding (ADR 0032 amends ADR 0011 only for the bucket; decision 9).
- **Release not affected (I3, I4) before exploitation signals.** An exploit for code the release does not ship does not apply.
- **A control (O1) before exploitation signals, but suspended by new ones.** A decision records the evidence it was made on; if a CVE is then added to KEV, crosses the EPSS threshold, or its severity rises, it is suspended and the finding falls through to N1 to N4.
- **Exploitation (N1, N2) before Debian's "unimportant" (I5).** A KEV listing or a high EPSS is evidence the CVE matters here.
- **End of life (N3) is not ignorable.** The tracker's `<end-of-life>` tag means a package "not anymore supported by the security team in a (old-)stable release" ([security_tracker.html](https://security-team.debian.org/security_tracker.html), as checked in the review); the tracker's JSON puts it in the urgency field. No fix will ever come, which is a reason to act (decision 2).
- **"Ignored" and "postponed" are not ignorable either.** `<ignored>` means "a valid/strong reason not to fix it" and `<postponed>` "a minor issue ... that may be fixed later" ([LTS team, CVE triage](https://lts-team.pages.debian.net/cve-triage.html)). Neither says the flaw cannot be exploited, so they are L4, overridden by N1, N2, or N4 (decision 4). The tracker itself hides them unless asked ("include issues tagged <no-dsa>", [tracker release view](https://security-tracker.debian.org/tracker/status/release/testing)).
- **Network exposure without agent data fails toward attention (N4)** (decision 8).
- **In-use evidence only escalates (N5), never demotes** (decision 27). A package a listening process loads is reachable while it runs, so its findings cannot be Low risk, and they add exposure points (VT-M3). A package not seen running is never demoted: the scan sees only what runs at that moment (not short-lived helpers, cron jobs, or `sftp-server` sessions), so "not seen running" does not mean low risk. There is no idle rule.

### Missing and stale data (B1, S3)

Missing data never makes a finding look safer, and stale data is still evidence:

- **Stale** (older than the source's age limit, decision 7): every rule keeps using the **last stored data**. A KEV-listed finding stays N1; an EPSS-high one stays N2 (KEV entries are almost never removed). Nothing is rewritten when a source goes stale or recovers. Staleness is a read-time qualifier: reasons, the tier, and the freshness line say "not re-checked against KEV since 2026-11-10", and badges that depend on the source are withheld. I5 is **held**: findings keep the I5 they had, from the last stored data, with the same qualifier.
- **Turned off** (the URL setting emptied): the last data is kept and goes stale, as above. Turning a feed off never lowers a score.
- **Never imported** (no stored data): N1 or N2 cannot fire and I5 does not apply (those findings fall to L4 or L5, more cautious than Ignorable). The tier and score are shown with "not checked against KEV" (or EPSS), never as a plain lower tier.
- **A CVE with no EPSS score** (EPSS lags new CVEs): N2 does not fire; its reason says "no EPSS score yet". I5 does not depend on EPSS, so EPSS being off or missing a CVE never moves a finding into or out of Ignorable.
- **No tracker entry** disables F2, I3, I4, I5, N3, and L4. **No listener evidence** (no in-use report, the scan off or failed, a kernel before 5.14, or a scan the server received 24 hours ago or more) leaves N5 unfired, so the finding is triaged as without it; in-use evidence never demotes a finding (decision 27). **No running kernel** disables I1, K1, and K2 (the image's findings are triaged by the other rules).

### Debian Security Tracker states and where they land

| Tracker state for the host's release | Rule |
|---|---|
| Resolved, fixed version newer than installed | F1 when the advisory data names a fix; otherwise F2 (S7) |
| Resolved, fixed version not newer than installed | I4 |
| Resolved with no version or `0` ("not affected") | I3 |
| Open, urgency `unimportant` | I5, unless N1 or N2 |
| Open, urgency `end-of-life`, or `<removed>` and still installed | N3 |
| Open, no-DSA (none, postponed, ignored) | L4, unless N1, N2, or N4 |
| Open, urgency low, medium, high, or not yet assigned | N1 to L5 by the other rules |
| Undetermined, or no entry | N1 to L5, without F2, I3 to I5, N3, or L4 |

Meanings: the tracker's `status/unimportant` page lists issues "considered unimportant from a security perspective ... thought to be unexploitable or uneffective in most situations" ([tracker](https://security-tracker.debian.org/tracker/status/unimportant)), and security_tracker.html defines `unimportant` as "does not affect the Debian binary package(s)" (as checked in the review); LTS triage: "not-affected ... when [the] version is not affected".

## VT-M2: Exploitation and exposure signals

| Signal | What it is | Licence and terms | Update and size | How it is fetched |
|---|---|---|---|---|
| **CISA KEV** | "The authoritative source of vulnerabilities that have been exploited in the wild" ([cisa.gov/kev](https://www.cisa.gov/kev)): CVE, date added, due date, required action, and known ransomware use. | CC0, public domain, "identical to CISA's own KEV license" ([cisagov/kev-data](https://github.com/cisagov/kev-data)). | Updated when CISA adds entries; the mirror syncs "usually shortly after cisa.gov, on weekdays" ([kev-data README](https://raw.githubusercontent.com/cisagov/kev-data/main/README.md)). 1,748 entries in October 2026 ([Safeguard](https://safeguard.sh/resources/blog/cisa-kev-catalog-by-the-numbers-2026)): 1 to 2 MB of JSON. | Default `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` (the mirror; cisa.gov's front has refused automated clients, as the review reports); alternative `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Every 6 hours with the advisory refresh, conditional request; offline import task. |
| **FIRST EPSS** | A daily probability (0 to 1) that a CVE sees exploitation activity in the next 30 days, and its percentile. It is not a severity. | Free to use; attribution asked "where possible", for example "See EPSS at https://www.first.org/epss" (FIRST's usage terms at [first.org/epss](https://www.first.org/epss/); quoted here from [a mirror](https://open.windriver.com/info/uni-license-list/licenses/first-epss-usage.html), since first.org could not be fetched while writing; the review confirmed the terms). | Daily, shortly after 13:30 UTC ([Safeguard](https://www.safeguard.sh/resources/blog/epss-api-or-daily-csv-which-to-use)). About 250,000 rows when [GitLab](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/epss/decisions/001_export_all_epss) measured, growing about 30,000 a year, so about 300,000 now; under 10 MB raw. | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`, daily at 14:30 UTC. It redirects: redirects are followed only to hosts named in a setting, and the build records the current target in "Outbound access" (N1). The first line names the model version and date. Only CVEs named by stored advisories are kept. The API is for lookups, not bulk, and is not used. Offline import task. |
| **CVSS v3 vector** | Already stored. "Network" when "the vulnerable system is bound to the network stack", local when it is not ([SSVC: CVSS attack vector](https://certcc.github.io/SSVC/reference/decision_points/cvss/attack_vector)); privileges and user interaction too. Shown to operators in words ("network, no login, no user action"), with the vector as secondary text (N7). | Part of the OSV records. | With the advisory data. | Parsed into columns on `advisories` at import (VT-S04). v2 and v4 vectors are not parsed. |
| **Debian scope** | Local or remote, per CVE (already stored). | ADR 0022. | | Used only when there is no CVSS vector. |
| **In use on the host** | Listening services and their packages (no new privilege), and, where the VM enables it, library use ([VT-APPLICABILITY](vt-applicability.md)). | Reported by the agent. | With each package report. | Agent, read-only. |

The server fetches every feed; agents need no internet access. Each new feed follows the existing pattern (P2-S13, P2-S16): verified HTTPS, a download limit, a time limit, conditional requests, a truncation guard, freshness, failures on the failed-jobs page, an offline import task, and a URL setting that, when empty, stops the refresh and keeps the last data.

### How established tools present this, and what is taken

- **SSVC** (CERT/CC, CISA) decides with named decision points rather than a score: Exploitation (none, public PoC, active), Exposure (small, controlled, open), Automatable, and impact ([SSVC overview](https://certcc.github.io/SSVC/ssvc_overview)); CISA's outcomes are Track, Track*, Attend, Act ([cisa.gov/ssvc](https://cisa.gov/ssvc)). **Taken:** a small decision tree on inspectable points, each outcome saying which point decided it. N1 is SSVC's "active" exploitation; N4 is "open" exposure plus "automatable".
- **Tenable VPR** is a proprietary 0.1 to 10 score, and "Tenable does not customize these values for your organization" ([Tenable](https://docs.tenable.com/nessus/Content/RiskMetrics.htm)). **Not taken:** a learned score cannot explain itself.
- **Qualys TruRisk** sums severity-weighted detection scores per band, scaled by asset criticality ([Qualys](https://docs.qualys.com/en/vmdr/latest/threat/calculating_asset_risk_score.htm)). **Taken:** a host score as a weighted sum by band. **Not taken:** its detection score and asset criticality (decision 13).
- **Snyk's priority score** adds factors for severity, exploit maturity, reachability, fixability, recency, and social trends ([Snyk](https://docs.snyk.io/manage-issues/issue-management/priority-score)). **Taken:** fixability and exploit maturity as separate factors. **Not taken:** recency and social trends.
- **Wiz**: "Installed-but-not-running findings drop in priority", "Internet-facing assets jump to the front of the queue", KEV is a "high-confidence urgency signal" ([Wiz](https://www.wiz.io/academy/vulnerability-management/vulnerability-prioritization)). **Taken:** a listening process as an escalation (N5), KEV first (N1). **Not taken** (decision 27): lowering installed-but-not-running findings, since not seen running does not mean low risk.

## VT-M3: Exposure tier and score

The **tier** is the headline and the first sort key; the **points** order hosts within a tier (S6, as #253 orders packages lexicographically).

**Tier**: **Known exploited** if any KEV advisory is in Needs attention or Fix available, or under a control (O1); else **Exposed, no fix** if any critical or high is in Needs attention; else **Fixes waiting** if any critical or high is in Fix available; else **Low** if any points; else **Minimal**. Accepted risks keep their bucket, so they keep their tier (S1). Not evaluated hosts have neither.

**Points per open advisory on the host**, counted once per host in its worst bucket however many binary packages it matches:

| Bucket | Critical | High | Medium | Low or unknown |
|---|---|---|---|---|
| Needs attention (accepted risks included) | 40 | 20 | 8 | 2 |
| Fix available | 20 | 10 | 4 | 1 |
| Low risk by a control (O1) | 10 | 5 | 2 | 1 |
| Low risk | 2 | 1 | 0 | 0 |
| Ignorable | 0 | 0 | 0 | 0 |

A KEV-listed advisory scores double, except in Ignorable. A finding of a package a listening process loads (N5's evidence, in whatever bucket it ends up) adds exposure points on top; VT-SCORES sets how many, more for a network listener than a loopback one (decision 27). The values are a published constant (decision 13). The host tab shows the breakdown ([tiles.html](../../mockups/vuln-triage/tiles.html#score)). Severity is the normalised severity (ADR 0011), never Debian's urgency.

Points and tier depend on KEV membership, which the bucket alone does not capture (a KEV listing on a Fix available finding changes no bucket). So the finding stores a `kev` flag beside its bucket, written whenever it changes, and the summary triggers recount on it (S2). EPSS changes points only through the bucket.

**Fleet:** no single fleet score. The fleet shows hosts per tier, the bucket totals, and the burn-down.

## VT-M4: Work and progress, in one unit

A **work item** is one action an operator takes on a host:

- **Upgrade a source package** that has Fix available findings by F1 or F2 (openssl covers `openssl` and `libssl3t64`). The update task can do these.
- **Install a new kernel package** (K2). The update task holds new packages back (DEC-16), so this is a documented manual step (`apt full-upgrade`, or `apt install linux-image-amd64`), counted until a newer image is installed.
- **Reboot into the installed kernel** (K1, or a reboot flag from the agent).

Needs attention advisories with no decision are **decisions due**, listed beside work but not counted as work, since there may be nothing to do.

**Progress**, last 30 days = work items done ÷ (done + remaining now), with findings cleared as secondary text. A work item is **done** when, and only when, the host's own reports show the action:

- an upgrade: a package report changed the installed version of a source package, and that resolved at least one Fix available finding (advisory data corrections never count, S5a);
- a kernel installed: a package report shows a newer image that turns K2 findings into K1;
- a reboot: the running kernel changed and K1 findings moved to I1 (they do not resolve, so counting resolutions would give a reboot no credit).

The host's transitions write these as work events (`vulnerability_work_events`, time-partitioned like other history, ADR 0027, kept 90 days). Progress is shown **on the host tab and the host summary tiles only**, read for one host on view; the fleet list and the Risk page show work remaining, not progress (S5c). With nothing done and nothing remaining it says "Nothing to install", not 100%.

Units on the screens: **buckets count findings** (they must add up to the open count), **work and progress count work items**, and the **score counts advisories** (so one CVE on two binary packages is not double-counted). The screens name the unit every time.

## VT-M5: Gamification, and the rules that keep it honest

What motivates: a meter that moves when work is done, a run to keep, a short list of the most exposed hosts and the most work, and quick wins ("upgrade openssl: clears 162 findings on 8 hosts").

Honesty rules (acceptance criteria for VT-SCORES and VT-RISK-PAGE):

1. A badge states its exact claim and scope in its words, never "secure", "safe", "clean", "compliant", or "protected", and its words are true at the moment shown.
2. No badge, run, or meter on a host that is not evaluated, or whose package report is older than 3 days (decision 7), or when the data a badge depends on is stale; the place says "withheld" and why.
3. "Nothing to install" always shows the Needs attention count beside it when that is not zero.
4. Nothing rewards lowering Low risk or Ignorable counts. Removing old kernels is a "tidy-up" quick win that says it changes no exposure.
5. A run has a 7-day grace for a new fixable critical (decision 7). During the grace the badge says so: "12-day run · 1 fixable critical, 4 days left". After the grace the run ends.
6. Rankings are of hosts and work, never of people.
7. Jumps the operator did not cause (an advisory import, a feed change) are marked on the burn-down.
8. Accessibility: words plus shapes, never colour alone; native `<meter>` with numbers in text; SVG charts with a title, a description, and a table; nothing moves on its own; no JavaScript needed; the app's CSP (no inline styles or scripts).

## VT-M6: Computed where, and at a million hosts

| What | Where | Cost grows with |
|---|---|---|
| Fixed version of an open finding | Chunk verdict (exists) | distinct chunks (ADR 0028) |
| Base bucket of a verdict (every rule that does not depend on the host) | `chunk_matches.base_bucket`, `base_rule`, `kev`, recomputed for the chunks holding advisories whose inputs changed | distinct chunks |
| Bucket, rule, and KEV flag of each open finding | Columns on `vulnerability_findings`, written by the host's transitions from the base bucket plus the host's own rules (I1, K1, K2, O1, N5), only where they changed | the host's findings, per host |
| Re-triage after a signal changes | `EvaluationRun::Triage`: chunks whose base changed, then the hosts on sets holding them (ADR 0028's path), in batches sized by lock time. KEV runs at once; EPSS and tracker changes are coalesced into one run a day. Staleness rewrites nothing | hosts on sets holding changed chunks |
| Re-triage after a host fact changes (kernel, listener evidence or its expiry after 24 hours, decision) | That host's transitions | one host |
| Per-host bucket counts, work items, KEV open, points, tier, decisions due, run timestamps | Columns on `host_compliance_summaries`, recounted by the existing triggers (ADR 0026) | one host per changed host |
| Fleet totals, hosts per tier | One sum over active summaries | the narrow summaries table |
| Fleet list and leaderboards by tier then points, or by work | Keyset pages on summary indexes | constant per page |
| Progress | Work events for one host, on its page | one host |
| Burn-down | `vulnerability_daily_totals`, written once a day from the summaries, kept 400 days | days |
| Quick wins | `vulnerability_quick_wins`, built **once a day** (S12) | see below |

**Daily re-triage volume (S3).** A tracker change re-triages hosts only when it changes a chunk's base bucket. Most kernel churn (urgency "not yet assigned" becoming low or medium) leaves a local-only kernel CVE in L2 and changes no base bucket; a change to or from `unimportant`, `end-of-life`, no-DSA, or a fixed version does. The tracker import records no change counts today (P2-D08), so VT-BUCKETS first adds a count of changed trixie entries per import and measures 14 days of it on the test VM; the estimate is then hosts per affected chunk times changed base buckets per day, recorded in the spec before the runs are built. Coalescing tracker and EPSS changes into one daily run bounds it to one pass a day.

**Quick wins at scale (S12).** ADR 0028 measured whole package sets as 78% (homelab template) to 96% (hand-managed) distinct, so at a million hosts sets are nearly as many as hosts, and "per chunk, then sets, then hosts" costs about candidates times hosts. The plan instead reads the open findings in Fix available through a partial index (`bucket = fix`), grouped by advisory and package, mapped to source packages: about hosts times Fix available findings per host (78 on the example host; 78 million rows at a million hosts), one index scan a day. VT-RISK-PAGE measures it at 100,000 hosts with 4,000 findings per host and records it before it is accepted. Building it once a day, labelled "as of", bounds the cost.

**Benchmarks** for every slice use about 4,000 open findings per host (the example host has 3,765), not the seed's 450.

An advisory every host has, added to KEV, re-triages every host's finding for it: about the cost ADR 0028 measured for an advisory's fan-out (about 20 minutes of one worker at a million hosts), with fleet counts a few minutes behind meanwhile.

## VT-D01: Mockups (approved 2026-11-19)

Static HTML in [`docs/mockups/vuln-triage/`](../../mockups/vuln-triage/index.html), approved by the owner on 2026-11-19 in PR #265: `index.html`, `host-vulns.html`, `fleet.html`, `risk-overview.html`, `override.html`, `tiles.html`, `states.html`, `data-sources.html`.

### Acceptance criteria

- [x] The owner has approved the mockups (PR #265, 2026-11-19)
- [ ] Every bucket, rule family, signal, and honesty rule above is drawn somewhere, and no screen uses colour alone

## Slices, in build order

1. [VT-FIXABLE](vt-fixable.md): store whether each open finding has a fix, count it, filter by it (folds in #252).
2. [VT-SIGNALS](vt-signals.md): import CISA KEV and FIRST EPSS, parse CVSS vectors.
3. [VT-BUCKETS](vt-buckets.md): the classifier (including the kernel rules, which need no agent change), base buckets on chunks, stored buckets and KEV flags, work events, re-triage runs, summary counts.
4. [VT-HOST-TAB](vt-host-tab.md): the host tab with buckets, reasons, work, and progress.
5. [VT-SCORES](vt-scores.md): tier and points on the summaries, the fleet list, and the tiles; adds the score breakdown and the run badge to the tab.
6. [VT-OVERRIDES](vt-overrides.md): controls and accepted risks; adds the decision links to the tab.
7. [VT-APPLICABILITY](vt-applicability.md): listening services and the reboot flag from the agent (no new privilege), and the optional library scan; adds the in-use signals to the tab.
8. [VT-RISK-PAGE](vt-risk-page.md): the fleet Risk page.

The **first cut** is 1 to 5 (decision 21): it answers "what is fixable, what needs attention, what can be ignored, and which hosts have the most work or the worst exposure" with no agent change and no new privilege.

## Acceptance criteria (the whole epic)

- [ ] Every open finding on an evaluated host is in exactly one bucket with a rule id and a readable reason, and the four bucket counts add up to the open count on the host tab, the fleet list, and the Risk page
- [ ] No finding moves to a less cautious bucket, and no score or tier drops, because data is missing, stale, or turned off; and no badge implies a host is safe. One exception (decision 28, decided by the owner on 2026-11-22): when N5's evidence expires (24 hours after the server received the scan) or is withdrawn (a failed scan, the scan turned off, no in-use report), an escalated finding returns to the bucket the other rules give it, and never goes below it
- [ ] Fleet pages cost the same per page at a million hosts as at 50 (measured with `bin/benchmark`), and nothing is computed per host times findings on a page view

## Decided by the owner (2026-11-19)

The owner approved the proposal on 2026-11-19 (PR #265) and answered all 26 open questions with their recommended defaults. The mockups (VT-D01), [ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md), and [FR-2.6](../../requirements.md#fr-26-vulnerability-triage-and-risk-exposure) are approved.

1. **Four buckets.** "Not fixable" splits into Needs attention and Low risk: Fix available, Needs attention, Low risk, Ignorable.
2. **Debian end-of-life** is Needs attention (rule N3), not Ignorable.
3. **Debian unimportant** is Ignorable (rule I5) once KEV data exists; KEV and EPSS (N1, N2) override it.
4. **No-DSA, postponed, ignored** are Low risk (rule L4) unless an exploitation or exposure rule matches first.
5. **Bucket names:** "Fix available", "Needs attention", "Low risk", "Ignorable".
6. **EPSS threshold:** enter at 0.10, leave below 0.07, as settings.
7. **Age limits and grace periods:** KEV and EPSS stale after 7 days; badges withheld when the package report is older than 3 days; a 7-day grace for a run; all settings.
8. **Network exposure before the agent reports use:** unauthenticated, network-reachable findings of medium or higher stay in Needs attention (N4) on hosts with no in-use report.
9. **Debian's fixed version for Fix available (F2):** used when the advisory data lags, for the bucket only, never to resolve a finding (ADR 0032 amends ADR 0011 there).
10. **Kernels:** images not running and kernel headers Ignorable (I1, I2); the running image's fixes as "reboot" (K1) or "install the new kernel package, then reboot" (K2), K2 a documented manual step. No kernel-install catalog task.
11. **New outbound sources:** KEV (the GitHub mirror by default, cisa.gov as the alternative) and EPSS on by default, each with a URL setting and an offline import task.
12. **Accepted risks** keep their bucket, points, and tier, marked, and leave "decisions due"; only a recorded control moves a finding to Low risk, scored above plain Low risk.
13. **Score:** the tier is the headline and first sort key, then points from the table as written (40/20/8/2, 20/10/4/1, 10/5/2/1, 2/1/0/0, KEV doubled, each advisory once per host). No per-host weight.
14. **Second factor for decisions:** not required, except one action covering more than 10 hosts. (Replaced by decision 37: counted per session, and always on a KEV-listed advisory.)
15. **Decision limits:** reason required (10 to 1,000 characters), at most 90 days (30 for KEV), only on Needs attention and Low risk findings, controls confirmed host by host.
16. **Host tab section order:** Fix available first.
17. **Host tab count:** "N to act on" (Fix available plus Needs attention); the open count stays in the heading.
18. **Host summary tiles:** "Open vulnerabilities" becomes "Vulnerability exposure" and "Work remaining"; the Packages tile is dropped.
19. **Fleet list:** sortable "Exposure" and "Work" columns replace "Open vulnerabilities"; hostname and tags move under the name.
20. **A Risk page** after Compliance in the top bar.
21. **First cut:** VT-FIXABLE (#256), VT-SIGNALS (#257), VT-BUCKETS (#259), VT-HOST-TAB (#260), VT-SCORES (#262) first; VT-OVERRIDES (#261), VT-APPLICABILITY (#258), and VT-RISK-PAGE (#263) after.
22. **#252** is folded into VT-FIXABLE (#256) and closed when PR #265 merges. Its answers: Q1 "Fix available"; Q2 yes, plus F2; Q3 not now; Q4 replaced by the bucket line and the fleet columns; Q5 the fleet-wide by-package page is deferred; Q6 yes; Q7 yes; Q8 a finding in this bucket of this severity; Q9 yes, host tab only, for package upgrades; Q10 the tab shows every bucket; Q11 no, the buckets use triage instead; Q12 severity first inside each bucket.
23. **In-use detection:** listening services from `/proc/net` and socket cgroups (no new privilege) in the main agent; the library scan only as a separate, short-lived unit with `CAP_SYS_PTRACE` and no network, off by default and enabled per VM.
24. **Suggested controls** come from a short table in the repository, advice only.
25. **Burn-down history** is kept 400 days.
26. **Milestone:** "Vulnerability triage", gated by `P2-ACCEPT` (#28), not gating Phase 3, created on GitHub at approval.

## Decided by the owner (2026-11-21)

27. **Scan evidence never demotes a finding; only listeners escalate** (2026-11-21, after the fourth review of #268; replaces L1 as approved on 2026-11-19 and the 2026-11-20 and 2026-11-21 decisions that refined it). "Not continuously running does not equal low risk, and trying to prove a package is never executed is a trap": an hourly snapshot cannot see short-lived helpers, cron jobs, or `sftp-server` sessions. So rule L1 ("idle") and N4's idle check are removed with their proof rules (the `native` list, on-demand directories, the D-Bus, timer, and cron parsing), and packages keep their standard bucket. Rule N5 puts a finding in Needs attention when a process holding a listening socket loads its package, by VT-APPLICABILITY's library scan (`loaded_by_listeners`); VT-SCORES adds exposure points for it, more for a network listener than a loopback one. The evidence lasts until 24 hours after the server received the report that carried the scan (by the server's clock), and a failed or turned-off scan, or a report without the in-use object, withdraws it at once; the finding then returns to the bucket the other rules give it, never below. That is the one exception to the second acceptance criterion, which names it (decision 28). The reason names the listener's package, its systemd unit, and up to 4 of its listening sockets. The mockups' L1 rows ("belongs to a service that is not running", "or idle") are superseded; VT-HOST-TAB updates them.

## Decided by the owner (2026-11-22)

28. **N5's evidence may lapse without lowering below baseline** (#268). When the evidence expires (24 hours after the server received the scan) or is withdrawn (a failed or turned-off scan, or a report without the in-use object), an escalated finding returns to the bucket the other rules give it, never below. This is the one exception to the second acceptance criterion, which says so.
29. **Escalation needs Linux 5.14 or later** (#268): the scan tells which processes hold a listening socket from `fdinfo`'s `ino:` line, and on an older kernel it escalates nothing, with a warning.
30. **Processes with a root filesystem of their own are skipped as listeners** (#268): a container's files are its image's, which the host's package lists would wrongly name. A chroot'd process (haproxy's workers, postfix's `smtpd`) counts.
31. **The agent soak samples open descriptors as the fewest of three counts half a second apart** (#268), so a report in progress is not counted as growth (`agent/scripts/soak.sh`, `docs/operations/agent-soak.md`).

Decided on VT-HOST-TAB's PR (#281):

32. **The host tab drops VT-FIXABLE's fix chips.** The bucket strip is the tab's only "Fix available". `?fix=available`, which the Compliance page and the fleet list link to, still shows exactly the findings they count, with a line saying how the bucket differs.
33. **The revised mockups are accepted.** This covers `host-vulns.html` (an N5 row, N4's example naming the listener, the new counts, and the Low risk wording true of every L rule), `states.html#no-in-use`, and `index.html`'s N5 row.
34. **Needs attention is ordered by worst severity first, with ties broken by KEV status** (known exploited first), then by advisory id. This is decision 22 Q12's "severity first inside each bucket".
35. **"Re-triage pending."** When a finding's stored rule no longer matches today's data (an input changed and the host's re-triage has not run yet), the tab says so rather than rebuilding the reason. The reason reads "When triaged: <the rule's summary> Re-triage pending: the data changed since this finding was triaged.", in the past and with no KEV or EPSS qualifier. The kernel row then says "Reboot into the newer kernel" with the same note, never naming a kernel that is running or gone.
36. **At most 200 findings are drawn under a package row** on the host tab, worst severity first. A last row says how many more match and links to the package page, which lists every finding of the package (paging it is #283). *Amended by #283 (PR #297), decided by the owner 2026-11-23:* the link opens the package page filtered as the tab is (its filters, the row's section and architecture, open findings) and starting after the last finding drawn, so it shows exactly the findings the row counts; the package page is paged, 50 a page, and with no filter still lists every finding of the package.

Decided on VT-OVERRIDES' PR (#299):

37. **The second factor for decisions is counted per session, and always asked on a KEV-listed advisory** (2026-11-23, after the review of #299; replaces decision 14's "one action covering more than 10 hosts"). A session that has recorded more than 10 host decisions within 15 minutes needs the TOTP step-up, counted on the server under the session's row lock, so splitting a request does not get around it. A decision on an advisory on CISA's KEV list needs a fresh code every time it is recorded or changed. Threat-model row H12.
