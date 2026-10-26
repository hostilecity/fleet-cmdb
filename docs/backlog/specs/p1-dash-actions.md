# P1-DASH-ACTIONS: Dashboard: create, edit, revoke, re-enroll, retire hosts

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- Create host form (name, hostname, description, tags) that shows the one-time enrollment token and the exact `fleet-agent enroll` command, once, with a clear warning that it cannot be shown again.
- Edit name, description, notes, and tags, with errors shown in place and before/after values recorded in the audit log.
- Revoke credential with explicit confirmation; immediate effect, visible state change.
- Re-enroll: issue a new token for a revoked or active host, with explanation of what happens to the old credential.
- Retire host with explicit confirmation that explains it revokes the credential and removes the host from the fleet counts.
- All actions are audited with the signed-in operator as actor.

## Acceptance criteria

- [ ] Every destructive action requires confirmation (retire, revoke) and is not reachable by a simple link
- [ ] Validation errors appear in place without losing input
- [ ] The token and command are shown once and never retrievable afterwards
- [ ] Each action creates the expected audit entry with before/after values
- [ ] AC-1.5: after Revoke in the UI, the agent's next request is rejected
