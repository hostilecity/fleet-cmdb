# Fleet simulator and load check

`cmdb/bin/simulate-fleet` (P1-O04) runs fake hosts against a local server through the real agent API: they enroll, send heartbeats and inventory reports on the agent's intervals, and can misbehave on purpose. It serves three purposes:

- **Development seed data:** a fleet of `sim-NNN` hosts (tag `simulator`) that stay online while it runs and go stale and offline when it stops.
- **The NFR-3 load check:** 50 hosts for one simulated hour, with accumulated snapshots, checked against the targets.
- **A scaled-down AC-1.2:** one host goes silent and the real liveness job must move it to stale, then offline, then back online when it resumes.

It is development and test tooling only. It refuses to run in production, and the application never loads it (`lib/fleet_simulator` is outside autoloading). To time the dashboard it allowlists `simulator@example.com` (audited) and gives that operator a session without Google, which only this tool does.

## Running it

Start the development server with higher enrollment limits, then run the simulator from `cmdb/`:

```sh
FLEET_ENROLL_RATE_LIMIT_PER_MINUTE=100 FLEET_ONBOARDING_RATE_LIMIT_PER_MINUTE=100 bin/dev
bin/simulate-fleet --hosts 50                     # 50 hosts on the default intervals for 10 minutes
bin/simulate-fleet --load-check --liveness-check  # NFR-3 and the AC-1.2 check, about 20 minutes
```

With the default limits it still works, waiting out each `429` as an agent would; enrolling 50 hosts then takes about five minutes. `bin/simulate-fleet --help` lists every option.

Credentials are kept in `tmp/fleet_simulator/credentials.json` (mode 0600), so a rerun brings the same hosts back instead of adding new ones. A host whose saved credential no longer works (revoked, or the database was reset) is enrolled again. To remove the simulated hosts, retire them in the dashboard or reset the development database (`bin/rails db:reset`).

| Option | Effect |
|---|---|
| `--enroll-via token` | Pre-registered hosts redeem enrollment tokens at `/api/v1/enroll` (the default). |
| `--enroll-via onboarding` | The installer's flow (DEC-17): each request is approved at once by the simulator's operator, then collected. |
| `--time-scale X` | Every interval divided by X, so a run covers X times its length in simulated time. |
| `--stop N` | N hosts go silent halfway through the run. |
| `--hostile N` | N hosts report markup, a right-to-left override, and zero-width characters in free-text fields. |
| `--churn N` | N hosts change their kernel version in every report, so a snapshot is written each time. |
| `--duplicates N` | N hosts resend every report with the same report id; each must be answered `duplicate: true` (AC-1.4). |
| `--seed-snapshots N` | Before the run, every host sends N reports with a changed stable field, through the API. |

Behaviours go to the last hosts in the list, so `sim-001` is always well behaved.

## The load check

`--load-check` runs 50 hosts for 15 minutes at four times the default rates (a heartbeat every 15 seconds, a report every 3¾ minutes), which is one simulated hour at four times the real request rate. Before the run each host sends 90 reports with a changed stable field, the history one change a day would leave within the default 90-day retention. The fleet list is loaded every 10 seconds, sorted by name and by status, as a signed-in operator.

It passes when:

| Check | Target |
|---|---|
| Hosts enrolled and reporting | at least 50 |
| Simulated time | at least one hour |
| Fleet list response, every load | under 2 seconds, and every simulated host listed (NFR-3) |
| Heartbeat p95, whole run and last quarter | under 200 ms (NFR-3: no degradation as snapshots accumulate) |
| Heartbeats and reports | every one accepted, and every resent report recognised |

Times are measured by the simulator from sending the request to reading the last byte of the response, so they include the network and the server's queueing; the browser's own rendering is not included. The development server is slower than production (no eager loading, verbose logging, three Puma threads), so a pass there is a conservative result.

`--liveness-check` sets the liveness thresholds to their minimum (online 1 minute, stale 2), silences one host 30 seconds into the run, and waits for the `LivenessEvaluationJob` that `bin/dev` runs to record stale and then offline, and for the host's next heartbeat to bring it online. Each step must happen within its threshold plus two minutes. The previous thresholds are restored afterwards, and both changes are audited.

The command exits 1 when a check fails. Results go to `tmp/fleet_simulator/<time>/` (or `--output`): `summary.md` for the delivery note, `summary.json`, and every request in `samples.csv`.
