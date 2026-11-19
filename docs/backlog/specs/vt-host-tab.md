# VT-HOST-TAB: Host Vulnerabilities tab with buckets, reasons, work remaining, and progress

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Part of [VT-EPIC](vt-epic.md) (proposed). Builds what [host-vulns.html](../../mockups/vuln-triage/host-vulns.html) draws, on top of #253's package groups ([P2-D04](p2-dash-host.md#p2-d04-host-vulnerabilities-view)), once the owner approves it.

## VT-D04: The tab

### Scope

- **Heading and strip.** "N open findings, by what you can do about them", the four bucket counts as links to their sections, and a proportion bar (SVG with a text equivalent). The tab's count in the tab bar becomes "N to act on" (Fix available plus Needs attention); the open count stays in the heading.
- **Work remaining** (epic VT-M4): the packages to upgrade, a pending reboot with the running and installed kernel versions, decisions due, and the existing "Apply package updates on this host" link into the create-task flow (#252 question 9: a link, never a direct POST; the task installs every pending update and never reboots).
- **Progress, last 30 days**: a native `<meter>` with the numbers in text; "Nothing to install" when there is nothing in either part; the streak badge with the honesty rules (epic VT-M5).
- **Sections**, one native `<details>` per bucket, in the order of epic question 14 (recommended: Fix available, Needs attention, Low risk, Ignorable); Fix available and Needs attention open by default, and a live refresh never closes one the operator opened (#253's `keep-open`).
  - Fix available: #253's package rows (same order, same keyset paging, same collapsed advisories), with an "Upgrade to" column and the in-use signal.
  - Needs attention: one row per advisory (its packages listed in the cell), severity, signals (KEV, EPSS, vector, in use), the reason, and the decision link or tag; then the suggested controls for the rules present (VT-S05's table).
  - Low risk and Ignorable: one row per rule with its count and largest package, each opening that rule's package rows; the reason text in full.
- **Reasons**: every advisory row shows its rule's sentence and rule id; Debian's triage line stays as P2-D08 built it.
- **Filters**: state, severity, text, and a signal filter (KEV, EPSS high, network without privileges, in use); `?bucket=` keeps one section. They combine with AND and stay in the URL; the bucket counts are over the open list whatever the other filters (as the triage chip is counted today).
- **Statements**: a fixed number whatever the host's finding count, as #253's tab; the bucket counts come from the summary row and one grouped query.

### Acceptance criteria

- [ ] The tab shows the four buckets with counts that add up to the open count, each finding with its reason and rule id, as drawn
- [ ] Work remaining names the packages to upgrade and a pending reboot, and the progress meter counts only fixable work
- [ ] The tab sends the same number of statements for a host with 10 findings and one with 6,000, and passes axe-core with no violations
