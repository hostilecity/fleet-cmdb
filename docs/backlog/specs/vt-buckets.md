# VT-BUCKETS: Put every open finding in exactly one triage bucket with a reason

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed); decided in [ADR 0032](../../decisions/0032-vulnerability-triage-buckets.md). The buckets, the rules and their order, and why, are the epic's VT-M1; this file says how they are built.

## VT-S05: The classifier, stored buckets, and re-triage

### Scope

- **Classifier.** `VulnerabilityTriage.classify(inputs)`: a pure function from one finding's inputs to `[bucket, rule_id]`, implementing VT-M1's table in order. Inputs: the verdict (fixed version, installed version, source), the advisory (normalised severity, `cvss_av`, `cvss_pr`, `cvss_ui`, CVE ids), Debian's triage for the host's release (status, fixed version, urgency, no-DSA, scope), KEV membership and EPSS band per CVE, the freshness of KEV and EPSS, the host's running kernel and in-use report, and an active decision with its evidence (VT-OVERRIDES). Unit specs cover every rule, every precedence pair in VT-M1, and every "missing data" case.
- **Reasons** are built at render time from the rule id and the same inputs, so wording can change without rewriting rows. The rule id is stored, not the text.
- **Applicability table** per distribution, `cmdb/config/triage_applicability.yml`, checked at boot, so other distributions (#163) are a data change: kernel image package pattern and how to get its kernel release (Debian: `linux-image-<release>` and `-unsigned`), the "no runtime code" packages of a source (Debian, source `linux`: `linux-libc-dev`, `linux-headers-*`, `linux-kbuild-*`, `linux-compiler-*`, `linux-doc*`, `linux-source-*`, `linux-support-*`), and the `kernel_build` version pattern.
- **Storage.** `vulnerability_findings.bucket` (smallint) and `bucket_rule` (smallint), null while resolved. The host's transitions compute them for its open findings in the same pass that writes the fix flag (VT-S01), with the inputs loaded in a fixed number of queries per batch, and write only rows that changed.
- **Re-triage runs.** `EvaluationRun::Triage`: started after a KEV or EPSS import, a Debian triage import, or an advisory import, with the advisories whose inputs changed (CVE added to or removed from KEV, EPSS band changed, tracker status, urgency, no-DSA, or scope changed for a fleet release, vector or severity changed). It finds their open findings by `advisory_id`, splits the hosts into keyset ranges, and runs each range's classification in batches locked in host-id order and sized by lock time (`LOCK_TARGET`, as #204 and #196). Runs supersede each other like advisory runs. A freshness change (a feed turning stale or fresh again) starts a run over the advisories it affects (those with KEV, EPSS high, or `unimportant`).
- **Host facts.** A new inventory (kernel, build, reboot flag), an in-use report, or a decision change re-classifies that host only, in its transitions.
- **Summaries.** `host_compliance_summaries` gains `vuln_fix`, `vuln_attention`, `vuln_low`, `vuln_ignorable` (finding counts), recounted by the existing triggers; the four always add up to `vuln_open`, checked by `compliance_summaries:check`.
- **Suggested controls** table, `cmdb/config/triage_controls.yml`: a short text per rule and attack vector (network service, crafted file, local privilege escalation, unsupported package, known exploited), our own words, for the host tab.
- **Measure** with `bin/benchmark`: a package report's transitions at 450 findings, a triage run for one advisory on 100,000 hosts, and the summary recount; record them here.

### Acceptance criteria

- [ ] Every open finding of an evaluated host has exactly one bucket and rule, the four summary counts add up to the open count, and resolved findings have none
- [ ] A rule that puts a finding in Ignorable or Low risk because of KEV, EPSS, tracker, or in-use data fires only when that data is present and current (spec per rule)
- [ ] A KEV import that adds one CVE re-triages only the findings of its advisories, and a host with nothing changed writes nothing
