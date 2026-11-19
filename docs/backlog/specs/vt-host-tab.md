# VT-HOST-TAB: Host Vulnerabilities tab with buckets, reasons, work remaining, and progress

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (approved by the owner, 2026-11-19). Builds what [host-vulns.html](../../mockups/vuln-triage/host-vulns.html) draws, on top of #253's package groups ([P2-D04](p2-dash-host.md#p2-d04-host-vulnerabilities-view)), approved 2026-11-19. Parts the mockup draws that need later slices are added by those slices (S9): the score breakdown and the run badge by [VT-SCORES](vt-scores.md), the decision links and tags by [VT-OVERRIDES](vt-overrides.md), and the in-use and listening signals by [VT-APPLICABILITY](vt-applicability.md). Until then those places are simply absent.

## VT-D04: The tab

### Scope

- **Heading and strip.** "N open findings, by what you can do about them", the four bucket counts (findings) as links to their sections, and a proportion bar (SVG with a text equivalent). The tab bar's count becomes "N to act on" (Fix available plus Needs attention, epic decision 17); the open count stays in the heading.
- **Work remaining** (epic VT-M4), in work items: the source packages to upgrade (the update task can do these), "install the new kernel package" when K2 applies (a documented manual step, since the task installs no new packages, DEC-16), "reboot into the installed kernel" when K1 applies, and decisions due beside them. The "Apply package updates on this host" link into the create-task flow (#252 question 9) says the task covers the package upgrades only: it installs every pending upgrade, no new packages, and never reboots.
- **Progress, last 30 days**, in work items: a native `<meter>`, "N of M work items done", with findings cleared as secondary text; done items come from work events (VT-S05), so advisory corrections never count. "Nothing to install" when there is nothing in either part. Shown here and in the host summary tiles only.
- **Sections**, one native `<details>` per bucket, in the order of epic decision 16 (recommended: Fix available, Needs attention, Low risk, Ignorable); Fix available and Needs attention open by default; `keep-open` as #253.
  - Fix available: the kernel row first when K1 or K2 applies (its action and the number of advisories it clears), then #253's package rows with an "Upgrade to" column.
  - Needs attention: one row per advisory (its packages listed), severity, signals (known exploited, EPSS, the attack vector in words), and the reason; then the suggested controls for the rules present.
  - Low risk and Ignorable: one row per rule with its count and largest package, each opening that rule's package rows.
- **Staleness qualifiers** at read time (epic VT-M1): when KEV or EPSS is stale or never imported, the freshness line and the affected reasons say so.
- **Filters**: state, severity, text, and a signal filter (known exploited, EPSS high, network without login); `?bucket=` keeps one section. They combine with AND and stay in the URL; bucket counts are over the open list whatever the other filters.
- **Statements**: a fixed number whatever the host's finding count; bucket counts from the summary row.

### Acceptance criteria

- [ ] The tab shows the four buckets with counts that add up to the open count, each finding with its reason and rule id, and a kernel fix as "reboot" or "install the new kernel package" rather than a package upgrade
- [ ] Work remaining and progress are both in work items, and progress counts only actions the host's reports show (an advisory correction counts nothing)
- [ ] The tab sends the same number of statements for a host with 10 findings and one with 4,000, and passes axe-core with no violations
