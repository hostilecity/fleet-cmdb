# Scale benchmark

`cmdb/bin/benchmark` measures what the server costs per agent request, per job run, and per dashboard page view, on a database seeded with a fleet far larger than the homelab. It answers "what breaks first, and when" with numbers that can be re-run after a change. The fleet simulator (`bin/simulate-fleet`, [fleet-simulator.md](fleet-simulator.md)) remains the NFR-3 acceptance check; the benchmark is for scale work.

It is development and test tooling only: every command refuses to run in production, and the application never loads it (`script/benchmark/` is outside autoloading).

## Procedure

Use a database of its own, so a seed never touches development data. From `cmdb/`:

```sh
export DATABASE_URL=postgres:///cmdb_bench QUEUE_DATABASE_URL=postgres:///cmdb_bench_queue \
       CACHE_DATABASE_URL=postgres:///cmdb_bench_cache CABLE_DATABASE_URL=postgres:///cmdb_bench_cable
bin/rails db:create db:schema:load

bin/benchmark seed --hosts 100000 --package-hosts 10000   # about 7.5 GB and 15 minutes on 2 CPUs (before #196)
# or, with the package hosts spread over 1,500 distinct package sets that share most of their chunks (ADR 0028):
bin/benchmark seed --hosts 20000 --package-hosts 5000 --package-variants 1500
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
| `seed` | Needs an empty database. Creates one template host through the real API and jobs (heartbeat, inventory, config and package reports, CIS evaluation, vulnerability matching, with the simulator's Phase 2 rules and advisories), then copies its rows in SQL to `--hosts` hosts, with history spread over 1.2 retention windows so pruning has work to do. A third of the hosts are "stable": all their inventory snapshots are older than the window. The history tables are partitioned by time (ADR 0027): the seed creates the partitions for the past it writes into and stores each row as received (`stored_at` = `received_at`), so retention finds partitions to drop, as on a server that has run that long. Prints each table's rows and bytes per row, the figures to extrapolate from. Package hosts point at the template's package set, or with `--package-variants N` at N sets derived from it (each upgrades 1 to 12 of its sources to one newer version and adds up to 2 of 20 tools; ADR 0028's prototype), and so do their snapshots. `--advisories-per-source N` imports N more simulated advisories for each of the simulator's 300 source packages before the template is matched, one in twenty with a fix, each naming a made-up CVE id (`CVE-2099-...`, for the triage probes): 5 gives the template 4,450 open findings, near a real Debian 13 host's (the vulnerability triage slices measure with it, VT-EPIC); 0, the default, keeps the simulator's 450. |
| `queries` | Each agent request in process through the whole Rails stack, for `--samples` hosts: wall and SQL time (median, p99), statements, rows, request and response bytes. `--verbose` lists the statements, so a review can see a new one. |
| `explain` | Runs each hot path (liveness, fleet list, compliance, task list, audit log, retention, advisory re-matching, CIS evaluation, vulnerability matching, the packages and vulnerabilities tabs, task jobs, host page) in a rolled-back transaction, and prints EXPLAIN (ANALYZE, BUFFERS) for every statement it sent. Sequential scans of large tables are flagged: those statements grow with the fleet. |
| `jobs` | Times the jobs whose cost grows with the fleet (median, min, max of `--repeat` runs) and the cost per host, chunk, or row. CIS evaluation and matching run once untimed first: the seed leaves findings that the first run reopens, and the first matching run matches the chunks. Matching is timed as host transitions (per host), every chunk matched again (per chunk), and an advisory import of one changed source: its chunks matched again (per chunk) and the whole re-match with the transitions of the hosts on them (per affected host). The triage probes (VT-BUCKETS) time, rolled back, a KEV listing of one CVE every package host has (the base of its verdicts, per chunk, then the run's re-triage of its hosts, per affected host), the base of 100 changed tracker CVEs (per CVE), every verdict's base again (per verdict), and `host_compliance_counts` (per package host). Retention is timed twice, rolled back: the row deletes (`Retention.prune!`: tables that are not partitioned, and a converted table's legacy partition) per row, and dropping the partitions past the window (`Retention.retire!`) per partition, with a line saying how many partitions, rows, and kept rows moved forward. |
| `load` | Closed-loop HTTP load, each request as the next seeded host: throughput, p50, p90, p99, status counts, payload sizes, and what the database did during the run: commits and rows written; for `hosts` and `host_liveness`, the updates, their HOT share, dead tuples, and how much the table and its indexes grew; and the write-ahead log the run made in the benchmark database (read back with `pg_walinspect`, which needs a superuser; other databases on the server are left out), by relation. `--kind mix` sends the default intervals' proportions (per agent per hour: 60 heartbeats, 120 task polls, 4 inventory reports, and one config and one package report every 6 hours). |

## Reading the results

- **Per request, not per run.** Statement counts and rows per request are exact and do not depend on the machine; times do. Compare times only between runs on the same machine with nothing else running, and repeat them (the median of three is the figure to quote).
- **Extrapolating.** A request's cost is per host and does not grow with the fleet when every statement is an index lookup. A statement that `explain` flags as a sequential scan, or a job whose time per host is constant, grows linearly: multiply by the fleet size. Request rates scale with the fleet on the default intervals: 1,000,000 agents send about 16,700 heartbeats and 33,300 task polls a second.
- **The seeded data.** Every host is a copy of the template, so data is more uniform than a real fleet (one OS, the same 800 packages unless `--package-variants` spreads them). Findings and package snapshots exist only for the first `--package-hosts` hosts, to stay within a few gigabytes; extrapolate their tables from the bytes per row. Package storage (ADR 0028) grows with distinct chunks, not hosts: divide the package tables by the package hosts only for the seed's own distribution.

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

### Retention by partition (#195, ADR 0027)

The same container, PostgreSQL 16, other suites running (load 4 to 6), so times are rough. Seed `--hosts 20000 --package-hosts 2000 --receipts 60 --audit-entries 10` (2 GB). The seed ran with `PGOPTIONS="-c session_replication_role=replica"`, which turns off every trigger and foreign key check while it copies rows (the compliance-summary triggers make the bulk copies 2 to 3 times slower, roughly linearly: the review of #239 measured 19.1 s against 8.0 s for 8,000 hosts × 40 rules); the history tables' rows are the same either way. `bin/benchmark jobs --only retention`, medians of 3, rolled back:

| What | Before (rows deleted, `main`) | After (partitions dropped) |
|---|---|---|
| Expired history | 3,642,179 rows deleted in 16.1 s (0.004 ms a row), plus their vacuum | 334 partitions (3,488,841 rows) dropped in 4.1 s, 12 ms a partition, 6,667 kept rows moved forward; 60,000 resolved findings still deleted by row (1.2 s) |
| A converted database (the same seed migrated) | | The five migrations took 15 s in all; the legacy partitions are retired once, one window after the upgrade: 4 million rows in 5.5 s, most of it moving each host's newest snapshots and status event forward (62,000 rows) |
| A report's duplicate check | unique index lookup | 0.15 to 0.19 ms over 12 receipt partitions (2 ms to plan the first time in a connection) |

A day's retirement in the steady state is one receipt partition of each type and, once a week, one partition of each weekly table: a few catalog operations whatever the fleet size.

### Package sets and per-chunk matching (#196, ADR 0028)

`seed --hosts 20000 --package-hosts 5000`, before on `main` (every package host the template's 800 packages) and after with `--package-variants 1500` (1,499 distinct sets, 859 chunks, 13,954 chunk entries). Same container, other suites running, development mode; times are rough, sizes exact. This is the favourable case, a template fleet; a hand-managed fleet, where most sets are distinct, is not measured. The findings' 306 bytes a row are those of a fresh database: an upgraded one keeps its wider rows until the table is rebuilt (docs/operations/upgrades.md).

| What | Before | After |
|---|---|---|
| Package lists and snapshots, per package host | 209 KB (`host_packages` 175 KB, JSON snapshots 34 KB) | 2.2 KB (sets 0.7 KB, chunk entries 0.5 KB, snapshot rows 0.9 KB) |
| Findings, per package host (450 each) | 173 KB (380 B a row) | 138 KB (306 B a row; lifecycle and `last_*`) |
| Vulnerability matching, per host | 122.5 ms (each host's own packages) | 6.7 ms (transitions from chunk verdicts); 1.7 ms per chunk to match a chunk again |
| Advisory import, one changed source (5,001 affected hosts) | 164 s, 32.9 ms per host | 0.08 s to match its 21 chunks again; 39.5 s with every affected host's transitions, 7.9 ms per host |
| Package report, 5 packages upgraded (in process) | 13 statements, 824 rows, SQL p50 57 ms | 12 statements, 10 rows, SQL p50 27 ms |
| Packages tab, one page (page 9; search "lib" page 2) | 5.8 ms; 1.3 ms | 4.6 ms; 3.0 ms |
| A host's open findings with their details (450) | 9.9 ms | 7.3 ms |

### Fix counts on the summaries (#256, VT-FIXABLE)

The same container, PostgreSQL 16, its default settings. Seed `--hosts 100000 --package-hosts 1500 --advisories-per-source 5` with triggers off, then `compliance_summaries:rebuild`: 6.68 million findings (1.93 GB), 4,450 open findings per package host, 650 of them with a fix. The seed's step that resolves "a fifth" of the findings resolves whole hosts when `--package-hosts` is a multiple of 5 (300 hosts here), so only hosts with open findings were sampled. Medians over 50 such hosts, each the median of 5 runs; other suites were running for part of it, so the ranges are of three runs.

| What | Before (`host_compliance_counts` v01) | After (v02) |
|---|---|---|
| The counts of one host | 4.0 to 5.0 ms | 4.9 to 5.2 ms |
| The counts of 50 hosts in one call (as a flush or the recount job batches them) | 193 to 202 ms | 260 to 318 ms |
| `host_compliance_summaries_refresh` of one host (lock, count, compare) | | 7.0 to 7.9 ms |
| Migration `20261120256001` (summary columns, functions) | | 18 ms; nothing is rewritten |
| Migration `20261120256002` (recount every host; 100-host batches since the re-check of #267) | | 25 to 27 s for 100,001 hosts (1,201 with open findings): run inline, since its estimate was 77 s (counted in 1.2 s) |
| One recount batch: 100 hosts with 3,560 open findings each (how long a flush for them can wait) | | 0.78 to 0.86 s |
| `compliance_summaries:recount_fixes` (the upgrade step), then the migration on restart | | 22.8 s; the migration then finds nothing left (14 ms) |
| `compliance_summaries:rebuild` | | 51 to 73 s |

The extra cost is about 1 ms a host with thousands of open findings (the distinct count of packages with a fix), paid only for hosts whose counts a transaction changed. `bin/benchmark explain` after: `/compliance` 5 statements, 113 to 134 ms; `?fix=available` and `?fix=available&vuln=high` 6 statements, 61 to 83 ms for both pages and the filtered count (the count reads the summaries, as the other filters' counts do); the recount probe 11.5 ms; the Vulnerabilities tab 10 statements as before, 89 ms, with the state and fix chips one grouped count of 5 ms; the tab filtered by `?fix=available` and `?fix=none` 41 ms for both pages.

### Exposure scores on the summaries (#262, VT-SCORES)

The same container (2 CPUs shared with other work, more loaded than for #256, so every figure here is about twice #256's), PostgreSQL 16 defaults. Seed `--hosts 100000 --package-hosts 1500 --advisories-per-source 5` (history options at 1): 1,201 hosts with 3,560 to 4,450 open findings each. The seed puts every finding in F1 or L5, so the 200 hosts measured had their findings rewritten to a realistic mix (about 650 Fix available with 30 K1, 50 Needs attention with KEV and listeners, 1,600 Low risk, 2,100 Ignorable): tier Known exploited, 4,900 to 6,200 points, about 250 work items each.

| What | Before (`host_compliance_counts` v03) | After (v04) |
|---|---|---|
| The counts of 200 hosts in one call, per host (median of 5, three rounds) | 11.6 to 11.9 ms | 16.0 to 17.9 ms |
| `host_compliance_summaries_refresh` of the same 200 hosts, writing nothing | | 2.7 to 3.6 s |
| One package host's recount (`bin/benchmark explain`): counts, then refresh | | 12.4 ms, then 14.8 ms |
| Fleet list sorted by exposure and by work, first and second page each (`explain`) | | 10 statements, 4.9 ms in all; each page an index read of 101 rows |
| `compliance_summaries:check` over 100,001 hosts | | 75 s, no drift |
| Migration `20261123262002`'s recount (`ComplianceFixRecount` on `compliance_score_recounts`) | | 53 s for 100,001 hosts; its estimate was 77 s with the fix counts' rates, about 2.5 minutes with its own (20 microseconds a finding, review of #305 N2), so the upgrade step |
| `20261123262002` writing each finding's listener in SQL (review of #305, S2): 1,501 hosts with evidence in force naming 40 packages each (20 network), 5.34 million open findings, separate seed of 20,000 hosts | | 288,240 findings written in 27 s, 18 ms a host with its commit and summary recount; run again, nothing to write, 3.6 s |

v04 reads a host's open findings once and groups them two ways in that pass (by advisory and by source package); a first version that scanned them twice cost twice v03. VT-FIXABLE's three columns are no longer counted, which saved about 2 ms a host. The extra 4 to 6 ms a host (+40%) is paid only for hosts whose counts a transaction changed, about 1.5 thread-hours per million recounts. The Compliance page's `?bucket=` filter, like its severity filters, reads the summaries without an index (32 ms here, a sequential scan of 100,001 narrow rows); the fleet-wide totals were already one sum over them. Requests in development mode against this seed (median of 5): `/` 277 ms, `/?sort=exposure` 253 ms, `/?sort=work` 269 ms, `/compliance` 279 ms, `/compliance?bucket=attention` 329 ms, a Known exploited host's Vulnerabilities tab 322 ms (294 KB), its Overview 81 ms. In headless Chrome at 1,280 px the fleet list's table is 1,166 px wide in its 1,166 px frame (1,291 px before the Exposure cell's lines were split); axe-core 4.14 reports no violations on `/`, `/?sort=exposure`, `/compliance`, the tab, and the Overview, at 1,280 and 390 px.
