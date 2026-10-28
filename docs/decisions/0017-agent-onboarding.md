# ADR 0017: Agent onboarding from the installer, approved in the dashboard

- Status: Accepted (owner, scope change #54)
- Decision issue: DEC-17
- Requirements: `FR-S.1`, `FR-1.1`, `FR-1.5`, `FR-1.6`, `NFR-1`, `AC-1.8`
- Amends: [ADR 0004](0004-enrollment.md). Operator-issued single-use tokens remain, as pre-registration for unattended installs; they are no longer the only way to enroll.

## Context

Enrollment under ADR 0004 needs an operator to create the host first, copy a token, and paste it into the VM. The owner wants a self-sufficient agent with minimal install steps. Open self-registration and a fleet-wide join secret were considered and rejected (below). The end state is enterprise scale ([ADR 0019](0019-scale-direction.md)), so the flow must also have a path with no person in the loop.

## Decision

Two ways to enroll, both ending in the same per-host credential (FR-S.1):

**1. Onboarding (interactive, the default).** Modelled on the OAuth device authorization grant (RFC 8628).

1. `sudo fleet-agent install --server https://agent.example.lan` sends `POST /api/v1/onboarding` with the facts needed to recognise the VM: hostname, operating system, machine ID, agent version. The endpoint is unauthenticated but served only on the private agent hostname (ADR 0005), rate-limited per client address, and capped in the number of open requests.
2. The server creates an **onboarding request**, not a host. It returns:
   - a **device code**: 32 random bytes, known only to the installer, stored as a digest;
   - a **user code**: 8 characters from an unambiguous alphabet, shown as `WDJB-MJHT`;
   - the approval URL on the dashboard hostname;
   - the expiry (default 10 minutes) and the polling interval.
3. The installer prints the URL and the user code (and a QR code of the URL) and polls `POST /api/v1/onboarding/token` with the device code.
4. A signed-in operator opens the URL, or the "Awaiting approval" list in the dashboard, and sees the reported facts, the client address, and the user code next to the add-host fields: name (prefilled from the hostname), tags, description, and notes. The operator confirms that the code matches the terminal and approves or rejects. If the reported machine ID or hostname matches an existing host, the page asks whether this is a **re-enrollment of that host** or a **new host**; nothing is attached to an existing host without that choice.
5. The installer's next poll collects the credential, exactly once. In the same transaction the host is created (`pending`, then `active`) with the operator's fields, or, for a re-enrollment, the existing host's credential is replaced as in FR-1.1. Both are audited, with the approving operator recorded.
6. Rejection, expiry, Ctrl-C, or never collecting leaves no host behind. Requests are pruned after expiry.

No secret is ever shown to a person: the user code only identifies a request, and the device code never leaves the installer.

**2. Pre-registration (unattended).** The ADR 0004 flow, renamed: an operator, or later an automation client, creates the host first and receives a single-use, expiring, per-host token for `fleet-agent install --token …` (cloud-init, templates, scripts). A leaked token is worth one host, once, before it expires.

**Rejected:**

- Open self-registration: anything on the LAN could create hosts, poison inventory, or impersonate a hostname.
- A fleet-wide join token: a long-lived shared secret that ends up in templates, scripts, and shell history; leaking it admits anyone until rotated.
- Revealing a token in the browser for the person to paste: an extra step that exposes a secret in the browser, clipboard, and shell history.
- Making "onboarding" a host enrollment state: unapproved, unauthenticated requests would sit in the hosts table and the fleet counts, and need transitions in the hosts guard.

## Consequences

- Install is one command plus one approval. `fleet-agent enroll` is replaced by `fleet-agent install` ([P1-AGENT-INSTALL](../backlog/specs/p1-agent-install.md)).
- New server work: onboarding requests, the two endpoints, expiry pruning, audit actions ([P1-ONBOARD](../backlog/specs/p1-onboard.md)), plus the approval page and the "Awaiting approval" list ([P1-DASH-ACTIONS](../backlog/specs/p1-dash-actions.md)). The existing enroll endpoint and tokens stay for pre-registration.
- The known weakness of the pattern is an operator approving someone else's request. It is mitigated by the code match, the reported facts and client address on the approval page, the short expiry, and operator sign-in on every approval. Phase 3's second factor (ADR 0006) can be required for approvals later.
- Operator approval does not scale to many thousands of hosts a day. At that scale pre-registration through an automation API, or attested identity, becomes the main path ([ADR 0019](0019-scale-direction.md)); onboarding remains for individual machines.
