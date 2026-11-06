# P1-VERIFY: Fleet simulator, load check, and agent soak test

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-O04: Fleet simulator and 50-host load check

### Scope

- A script (for example `cmdb/script/simulate_fleet.rb`) that enrolls N fake hosts via the real API (pre-registration tokens; onboarding with an auto-approving test helper for scale runs) and sends heartbeats and inventory on configurable intervals, with controllable behaviours: stop heartbeating, send hostile strings, change stable fields, resend duplicate reports.
- Doubles as development seed data and as an end-to-end check for liveness transitions with real timers (a scaled-down version of AC-1.2).
- A repeatable load check for NFR-3: 50 simulated hosts on default intervals for at least an hour of simulated time (time scaling allowed); record fleet list load time and heartbeat p95 and compare with the targets.
- Uses the shared example payloads from `docs/api/examples/` where possible.
- Delivered as `cmdb/bin/simulate-fleet` ([docs/operations/fleet-simulator.md](../../operations/fleet-simulator.md)). `--load-check` runs 50 hosts for 15 minutes at four times the default rates (one simulated hour) after each host has sent 90 reports with a changed stable field; times are measured by the simulator, from sending the request to reading the last byte.

### Acceptance criteria

- [ ] The simulator can bring up 50 hosts against a local server with one command
- [ ] Fleet list renders in under 2 seconds and heartbeat p95 is under 200 ms with 50 hosts and accumulated snapshots (numbers recorded in the delivery note)
- [ ] Stopping a simulated host produces the stale then offline transitions

## P1-A09: Agent soak test: no leaks over days

### Scope

- A repeatable soak script: run the agent against the [P1-O04](p1-verify.md) simulator or a test server with short intervals for at least 72 hours, including periods where the server is down or flapping. The 72-hour run itself is deferred to [P2-SOAK](p2-soak.md), so nothing is deployed in Phase 1; this section delivers the script and its analysis, checked by shorter runs on systemd.
- Sample the agent's resident memory, open file descriptors, thread count, and state-directory size at intervals and write them to a file.
- Include at least one update and one forced rollback during the run; staging and old versions must be cleaned up afterwards.
- Fail criteria: monotonic growth beyond an agreed tolerance, descriptor growth, or any state-directory growth.
- Findings and the raw samples of the 72-hour run attached to the Phase 2 delivery note ([P2-SOAK](p2-soak.md)); the shorter runs here are recorded in the pull request.
- Delivered as `agent/scripts/soak.sh` against the stand-in server `agent/scripts/update-stub.py`, judged by `agent/scripts/soak-analyse.py` ([docs/operations/agent-soak.md](../../operations/agent-soak.md)). Tolerances (agreed by the owner as the defaults), over the window after the rollback less a tenth for warm-up, last quarter against first: median resident memory at most 10% (and at least 1 MiB) higher; highest descriptor and thread counts no higher; no more state-directory entries and at most 512 bytes more (records rewritten in place).

### Acceptance criteria

- [ ] A run on systemd completes with flat memory, descriptors, and disk usage (the 72-hour run is [P2-SOAK](p2-soak.md))
- [ ] The agent survives repeated server outages during the run without restarting itself
- [ ] The script and results are committed or linked
