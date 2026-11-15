# Scale benchmark

`cmdb/bin/benchmark` measures what the server costs per agent request, per job run, and per dashboard page view, on a database seeded with a fleet far larger than the homelab. It answers "what breaks first, and when" with numbers that can be re-run after a change. The fleet simulator (`bin/simulate-fleet`, [fleet-simulator.md](fleet-simulator.md)) remains the NFR-3 acceptance check; the benchmark is for scale work.

It is development and test tooling only: every command refuses to run in production, and the application never loads it (`script/benchmark/` is outside autoloading).

## Procedure

Use a database of its own, so a seed never touches development data. From `cmdb/`:

```sh
export DATABASE_URL=postgres:///cmdb_bench QUEUE_DATABASE_URL=postgres:///cmdb_bench_queue \
       CACHE_DATABASE_URL=postgres:///cmdb_bench_cache CABLE_DATABASE_URL=postgres:///cmdb_bench_cable
bin/rails db:create db:schema:load

bin/benchmark seed --hosts 100000 --package-hosts 10000   # about 7.5 GB and 15 minutes on 2 CPUs
bin/benchmark queries                                     # statements, rows, and time per agent request
bin/benchmark explain                                     # EXPLAIN (ANALYZE, BUFFERS) of the hot paths
bin/benchmark jobs                                        # per-host cost of the fleet-wide jobs
```

For the HTTP load test, start a production-mode server on the same databases in another terminal (production settings, eager loading, quiet logs; one Puma process unless `WEB_CONCURRENCY` is set), then run the load from the first:

```sh
# Production's database.yml names the role cmdb; put your own role in each of the four URLs, for example
# postgres://YOUR_ROLE@%2Fvar%2Frun%2Fpostgresql/cmdb_bench for a local socket.
RAILS_ENV=production RAILS_LOG_LEVEL=warn SECRET_KEY_BASE=<64 characters> FLEET_ENCRYPTION_KEY=<32 or more> \
  FLEET_DASHBOARD_HOST=fleet.example.com FLEET_AGENT_HOST=agent.example.lan GOOGLE_CLIENT_ID=x GOOGLE_CLIENT_SECRET=y \
  DATABASE_URL=... QUEUE_DATABASE_URL=... CACHE_DATABASE_URL=... CABLE_DATABASE_URL=... PORT=3001 bundle exec puma -C config/puma.rb

bin/benchmark load --url http://127.0.0.1:3001 --agent-host agent.example.lan --kind heartbeat --threads 8 --duration 30
bin/benchmark load --url http://127.0.0.1:3001 --agent-host agent.example.lan --kind mix --threads 8 --duration 60 --warm
```

`load` checks that every host it will send as (`--first-host`, `--load-hosts`) has a seeded credential. A seeded host's inventory is a copy of the template's, so its first inventory report writes a snapshot; `--warm` sends each host that first report before the run, untimed, so `inventory` and `mix` runs measure steady reports.

`bin/benchmark --help` lists every option. Reset with `bin/rails db:schema:load` before seeding again, and drop the databases when done (`bin/rails db:drop`).

## What each command does

| Command | Measures |
|---|---|
| `seed` | Needs an empty database. Creates one template host through the real API and jobs (heartbeat, inventory, config and package reports, CIS evaluation, vulnerability matching, with the simulator's Phase 2 rules and advisories), then copies its rows in SQL to `--hosts` hosts, with history spread over 1.2 retention windows so pruning has work to do. A third of the hosts are "stable": all their inventory snapshots are older than the window. Prints each table's rows and bytes per row, the figures to extrapolate from. |
| `queries` | Each agent request in process through the whole Rails stack, for `--samples` hosts: wall and SQL time (median, p99), statements, rows, request and response bytes. `--verbose` lists the statements, so a review can see a new one. |
| `explain` | Runs each hot path (liveness, fleet list, compliance, task list, audit log, retention, advisory re-matching, CIS evaluation, vulnerability matching, task jobs, host page) in a rolled-back transaction, and prints EXPLAIN (ANALYZE, BUFFERS) for every statement it sent. Sequential scans of large tables are flagged: those statements grow with the fleet. |
| `jobs` | Times the jobs whose cost grows with the fleet (median, min, max of `--repeat` runs) and the cost per host or per row. CIS evaluation and matching run once untimed first: the seed leaves findings that the first run reopens. |
| `load` | Closed-loop HTTP load, each request as the next seeded host: throughput, p50, p90, p99, status counts, payload sizes, and the database's commits, rows written, and HOT update share for `hosts` during the run. `--kind mix` sends the default intervals' proportions (per agent per hour: 60 heartbeats, 120 task polls, 4 inventory reports, and one config and one package report every 6 hours). |

## Reading the results

- **Per request, not per run.** Statement counts and rows per request are exact and do not depend on the machine; times do. Compare times only between runs on the same machine with nothing else running, and repeat them (the median of three is the figure to quote).
- **Extrapolating.** A request's cost is per host and does not grow with the fleet when every statement is an index lookup. A statement that `explain` flags as a sequential scan, or a job whose time per host is constant, grows linearly: multiply by the fleet size. Request rates scale with the fleet on the default intervals: 1,000,000 agents send about 16,700 heartbeats and 33,300 task polls a second.
- **The seeded data.** Every host is a copy of the template, so data is more uniform than a real fleet (one OS, the same 800 packages). Package rows, findings, and package snapshots exist only for the first `--package-hosts` hosts, to stay within a few gigabytes; extrapolate their tables from the bytes per row.

## Reference results

From the scale assessment (November 2026): a container with 2 CPUs and 7 GB of memory, PostgreSQL 16 with its default settings (128 MB of shared buffers), other test suites running at the same time, `main` at the time. Times are medians; treat them as rough.

| What | Result at 100,000 hosts |
|---|---|
| Seed (`--hosts 100000 --package-hosts 10000`) | 14 minutes, 7.5 GB |
| Heartbeat, in process | 11 statements, 6 rows, SQL about 7 ms |
| Heartbeat over HTTP, one Puma process with 3 threads | about 95 requests a second, p99 100 ms; 8.4 ms of Ruby CPU and 2.5 ms of PostgreSQL CPU a request |
| Task poll over HTTP | about 115 requests a second; 7.3 ms of Ruby CPU and 2.4 ms of PostgreSQL CPU |
| Default-interval mix over HTTP | about 110 requests a second a process, so about 2,100 agents a Puma process |
| Package report (800 packages, gzip) | about 53 ms of Ruby CPU, half of it JSON Schema validation |
| Fleet list (`/hosts`), database time | 31 s (every host on one page, with compliance counts) |
| Compliance (`/compliance`), database time | 29 s |
| Liveness evaluation | 0.1 s a minute when nothing changes; 12.6 s when every host goes offline at once |
| CIS evaluation | 32 ms a host (development mode) |
| Vulnerability matching | 71 ms a host (development mode) |
