# ADR 0019: Design direction toward enterprise scale

- Status: Accepted (owner, scope change #54)
- Decision issue: DEC-19
- Requirements: `NFR-3`, `NFR-5`, design principles in `docs/requirements.md` section 2

## Context

The project is built and proven on a homelab of tens of VMs. The owner's intended end state is to take a fully tested prototype to enterprise scale: millions of devices. Rebuilding for that scale now would delay the prototype. Ignoring it would bake in choices that are expensive to undo, the most expensive being the agent protocol, because deployed agents outlive server releases.

## Decision

- **Acceptance targets stay at homelab scale.** NFR-3's 50-host figures are the acceptance bar for Phases 1 to 3. Nothing is built for scale ahead of need.
- **Choices that are hard to undo must not block scale.** When two options cost about the same now, take the one that scales. In particular:
  - **The agent protocol is the long-lived contract.** It must stay stateless to authenticate (key-id lookup, digest compare), pull-only, versioned, and tolerant of unknown fields (ADR 0008).
  - **The server controls load.** Agents honour `Retry-After` and must accept server-directed heartbeat and report intervals from the heartbeat response ([P1-AGENT-REPORT](../backlog/specs/p1-agent-report.md)), so fleet-wide load can be shed without an agent release.
  - **Enrollment and updates need no person in the loop.** Pre-registration ([ADR 0017](0017-agent-onboarding.md)) works unattended, and update artifacts are signed and location-independent ([ADR 0018](0018-signed-agent-updates.md)).
  - **Agent identity is per host and revocable.** No shared secrets, nothing an attacker can scale from one compromised VM.
- **Known limits accepted for the prototype.** These are recorded so nobody "fixes" them early, and so the scale-up plan starts from an honest list:
  - one PostgreSQL database, with a row lock and write per heartbeat;
  - a liveness job that scans all active hosts every minute;
  - Solid Queue and Solid Cable on the same database, and fleet counts recomputed per live broadcast;
  - deployment on one machine with Docker Compose (ADR 0005);
  - operator sign-in by Google allowlist (ADR 0006), not enterprise single sign-on with roles;
  - multi-tenancy, still out of scope;
  - Debian 13 on x86_64 only (ADR 0001).

## Consequences

- A future "scale-up" phase will replace the items in the known-limits list; each replacement needs its own ADR. The agent protocol and the trust model are intended to carry over unchanged.
- Reviews can reject a change that would make a known limit harder to remove, even when it passes at 50 hosts.
