# Mockups

Static HTML designs, reviewed and approved by the owner before the matching dashboard views are built (AGENTS.md).

- `phase-1/` covers the Phase 1 dashboard (P1-D01). Open `phase-1/index.html` in a browser to see the screen list. No server is needed.
  - The scope change in #54 ([ADR 0017](../decisions/0017-agent-onboarding.md), [ADR 0018](../decisions/0018-signed-agent-updates.md)) adds the install, approval, pre-registration, and agent rollout screens (P1-D06 in `docs/backlog/specs/p1-dash-actions.md`). `host-new.html` and `host-token.html` now show pre-registration. The index marks these screens "P1-D06 review".
  - The audit log (`audit.html`, `audit-states.html`) was reworked for P1-AUDIT-PAGE (#46, `docs/backlog/specs/p1-audit-page.md`): every action in `Audit::Actions::ALL`, filters in the URL, keyset pagination, and escaped values. The index marks these screens "#46 review".
- `phase-2/` covers the Phase 2 dashboard (P2-D01): host Configuration, Packages, and Vulnerabilities tabs, fleet compliance, rules management and import, advisory data sources, and every empty and "not evaluated" state. Open `phase-2/index.html` to see the screen list and the open design questions for the owner. It reuses `phase-1/mockup.css` (so keep `phase-1/` beside it) and adds `phase-2/phase2.css`. It makes no external requests, so fonts are the system stack. The index marks every screen "P2-D01 review" until the owner approves it.

Mockups use example data only (`*.example.lan`, documentation addresses, `EXAMPLE` tokens). Yellow dashed boxes are review notes, not part of the design.
