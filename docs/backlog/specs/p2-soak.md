# P2-SOAK: 72-hour agent soak run

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Deferred from Phase 1 ([P1-A09](p1-verify.md)) so that nothing is deployed before it is needed: the soak tooling was built and checked there, and only the long run remains.

## P2-A04: 72-hour agent soak run

### Scope

- Run `agent/scripts/soak.sh` for 72 hours (the default) on a disposable VM, as in [docs/operations/agent-soak.md](../../operations/agent-soak.md): server outages and flapping, one update, and one forced rollback, against the stand-in server.
- Judge it with `agent/scripts/soak-analyse.py` at the tolerances agreed in [P1-A09](p1-verify.md); change them only with the owner's agreement, recorded there.
- Use an agent built from the code at the time of the run, so the result describes the agent being accepted.
- Attach `summary.md` and `samples.csv` to the Phase 2 delivery note ([P2-X02](p2-accept.md)). A failure is a defect against the agent, fixed and followed by a new run.

### Acceptance criteria

- [ ] A 72-hour run completes with flat memory, descriptors, threads, and disk usage
- [ ] The agent survives repeated server outages during the run without restarting itself
- [ ] Only the current and previous versions remain installed after the update and rollback, with nothing left of staging
- [ ] The summary and samples are attached to the Phase 2 delivery note
