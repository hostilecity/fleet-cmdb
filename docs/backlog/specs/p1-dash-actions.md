# P1-DASH-ACTIONS: Dashboard: onboarding approval, pre-registration, and host actions

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Onboarding is decided in [ADR 0017](../../decisions/0017-agent-onboarding.md): an onboarding request approved here is the default way to enroll, and "create host" becomes pre-registration for unattended installs.

## P1-D06: Mockups for onboarding, pre-registration, install, and rollouts

### Scope

Static mockups in `docs/mockups/phase-1/`, delivered as their own pull request (`Refs` this issue) and approved by the owner before any of these views is built:

- **Onboarding approval page:**
  - the user code to confirm against the terminal;
  - the reported facts (hostname, OS, machine ID, agent version) and the client address;
  - the host fields, prefilled;
  - when the machine ID or hostname matches an existing host, the choice between re-enrolling that host and adding a new one;
  - approve and reject;
  - expired, already-decided, and unknown-code states.
- **The "Awaiting approval" list,** with a fleet-page notice linking to it.
- **"Pre-register host",** replacing `host-new.html` and `host-token.html`: the one-time token and the exact `fleet-agent install --token-stdin` command, shown once.
- **The agent install page** ([P1-D08](p1-releases.md)), **the agent versions and rollout page** ([P1-D09](p1-updates.md)), and the "Agent updates" section on host detail.
- **Updates to the existing pages:** the re-enroll dialog now explains both ways to re-enroll, and the top-bar navigation gains Agents.

### Acceptance criteria

- [ ] Owner has reviewed and approved the mockups in the PR
- [ ] Every screen named above, including its error and empty states, is represented, with example values only

## P1-D04: Host actions

### Scope

- **Pre-register host** form (name, hostname, description, tags). It shows the one-time enrollment token and the exact `fleet-agent install --token-stdin` command, once, with a clear warning that it cannot be shown again.
- Edit name, description, notes, and tags, with errors shown in place and before/after values recorded in the audit log.
- Revoke credential with explicit confirmation; immediate effect, visible state change.
- Re-enroll: issue a new token for a revoked or active host, with explanation of what happens to the old credential; or re-run the installer with `--reenroll` and approve the request as a re-enrollment ([P1-D07](p1-dash-actions.md)).
- Retire host with explicit confirmation that explains it revokes the credential and removes the host from the fleet counts.
- All actions are audited with the signed-in operator as actor.

### Acceptance criteria

- [ ] Every destructive action requires confirmation (retire, revoke) and is not reachable by a simple link
- [ ] Validation errors appear in place without losing input
- [ ] The token and command are shown once and never retrievable afterwards
- [ ] Each action creates the expected audit entry with before/after values
- [ ] AC-1.5: after Revoke in the UI, the agent's next request is rejected

## P1-D07: Onboarding approval

### Scope

- **`/onboard`** (the `verification_uri`):
  - Asks for the user code; `/onboard/<user code>` (the `verification_uri_complete`) prefills it.
  - Both require sign-in, and the code is carried through the sign-in redirect.
  - Code lookups are rate-limited per operator (20 a minute).
- **Approval page** as in P1-D06, built on `Onboarding::Approve` and `Onboarding::Reject` ([P1-S14](p1-onboard.md)).
  - Approve and reject are POST forms with CSRF protection.
  - A request that expired or was decided while the page was open shows that state instead of an error.
- **"Awaiting approval" list** of open requests, newest first, with their expiry. A notice on the fleet page appears while any are open, and updates live over the fleet stream ([P1-D05](p1-dash-fleet.md)).
- **Escaping.** All reported facts are agent-supplied and rendered escaped.

### Acceptance criteria

- [ ] AC-1.8 (dashboard half): approving with the matching code enrolls the waiting installer as a host with the entered fields, and rejecting leaves no host
- [ ] A matching machine ID or hostname is never attached to an existing host without the operator choosing it
- [ ] Anonymous requests to `/onboard` redirect to sign-in and return to the same request afterwards
