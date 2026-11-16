# Scaling the server

How to size the server past the homelab, and the steps after that. The defaults are right for one VM with a few hundred agents; nothing here is needed below about 2,000. The capacity figures come from the scale benchmark (`bin/benchmark`, [benchmark.md](benchmark.md), from #188); re-measure with it after each step (#198, [ADR 0025](../decisions/0025-first-scale-step.md)).

## Today: one container

| Process | Count | Threads | Setting |
|---|---|---|---|
| Puma | 1 (`WEB_CONCURRENCY` unset) | 3 | `RAILS_MAX_THREADS` |
| Solid Queue supervisor, dispatcher, scheduler | 1 each | | |
| Solid Queue worker, realtime queue only | 1 | 1 | `JOB_REALTIME_THREADS` |
| Solid Queue worker, default queue (and realtime when free) | 1 (`JOB_CONCURRENCY`) | 3 | `JOB_THREADS` |
| Solid Queue worker, evaluation queue only (#197) | 1 | 2 | `EVALUATION_THREADS` |

All of them run in the `fleet-cmdb` container: Solid Queue starts inside Puma (`SOLID_QUEUE_IN_PUMA`). One PostgreSQL server holds the four databases: primary, queue, cache, and cable.

**The realtime queue (S-7).** The jobs that run every minute (liveness, task leases, task expiry, rollout timeouts, report request expiry) and the dashboard's live refreshes run on the `realtime` queue. A worker serves only that queue, so a long advisory refresh, upload import, or matching run can never take its thread. The default worker serves `default`, Solid Queue's own `solid_queue_recurring` (the hourly clean-up of finished jobs), and then `realtime`, so it helps with realtime jobs when it has a free thread. A third worker serves only `evaluation`, the batches of fleet-wide CIS evaluation and advisory re-matching (#197), so a fleet-wide run never holds the default threads. No worker serves `*`: Solid Queue cannot leave a queue out of it. Within the realtime queue the every-minute jobs run before the refreshes, so a burst of changes cannot hold them up either. `spec/config/queue_spec.rb` runs the workers and checks this, and that every queue a job or recurring task uses has a worker.

Measured on 2 CPUs, with three jobs of 150 s each holding every default thread (`SolidQueue::RecurringJob` running `sleep 150` on the default queue), the delay of each liveness evaluation from its scheduled minute:

| | While the long jobs ran |
|---|---|
| Before (one worker for every queue) | 94 s, then 34 s: each waited for a long job to end |
| After (a realtime worker) | 0.3 s to 0.8 s every minute |

`TaskLeaseJob` showed the same delays. The realtime worker is one more process: about 55 MB (proportional set size, shared pages split), and about one more connection to each of the primary, queue, and cable databases.

## How much one process serves

- **One Puma process** serves about 110 agent requests a second on the default intervals (`bin/benchmark load --kind mix`), at 80 to 86% of one core. On the default intervals each agent sends 0.051 requests a second (per hour: 60 heartbeats, 120 task polls, 4 inventory reports, and a config and a package report every 6 hours), so **one Puma process serves about 2,100 agents**.
- **More threads do not help.** With 3 threads one process is already at 80 to 86% of a core, and Ruby runs one thread of a process at a time, so more threads mostly wait. Keep `RAILS_MAX_THREADS` at 3 and add processes.
- **PostgreSQL** spent about 2.5 ms of CPU per request beside Puma's 8.4 ms, so on one VM about a quarter of the cores go to the database.
- **Memory:** about 105 MB for one Puma process and about 230 MB for Solid Queue's five processes (proportional set size, measured on a 3,000-host test fleet). Check yours with `docker stats` after adding processes.

## Step 1: up to about 10,000 agents

All of it is configuration on the same VM. Change the settings in GitHub (`FLEET_EXTRA_SETTINGS`, one `NAME=value` per line, or the variable `FLEET_JOBS_CONTAINER`) and run the Deploy workflow.

### Puma processes: `WEB_CONCURRENCY`

Requests a second = agents x requests per agent a second. Processes = that / 110, rounded up, and no more than the cores left after PostgreSQL and the jobs.

| Agents | Task poll every 30 s (default) | Task poll every 300 s (#190) |
|---|---|---|
| Up to 2,000 | 1 (unset) | 1 |
| 5,000 | 3 (255 requests a second) | 1 (106) |
| 10,000 | 5 (510) | 2 (212) |

These leave little headroom: add a process for bursts, such as every agent reporting after an outage.

With 5 processes, plan on 6 to 7 cores for one VM: about 4.3 for Puma, 1.3 for PostgreSQL, and the rest for jobs. `WEB_CONCURRENCY=auto` starts one process per core, which leaves none for PostgreSQL on the same VM; set a number instead.

### Report load shedding: `FLEET_REPORT_MAX_IN_FLIGHT`

Off by default. Set it to 2 (one less than `RAILS_MAX_THREADS`) once one process serves thousands of agents: a report that arrives while 2 are in flight in that process gets `503 overloaded` with `Retry-After` (30 to 45 s, `FLEET_REPORT_RETRY_AFTER_SECONDS`), so one thread is always free for heartbeats and hosts never go offline because of a report surge. The agent keeps the report and comes back after `Retry-After` (#200). A shed request costs no authentication and no database work, and an address over the failed-authentication limit never takes a slot. Watch the log for `[agent_api] shed`: steady shedding means the process count is too low, not a fault. Leave it off for `bin/simulate-fleet --load-check`, which sends 16 requests at once on purpose.

### Job workers: `JOB_THREADS`, `JOB_CONCURRENCY`, `JOB_REALTIME_THREADS`, `EVALUATION_THREADS`

- Raise `JOB_CONCURRENCY` (processes) before `JOB_THREADS` (threads in each): the long jobs (advisory refresh and import, per-host matching) are Ruby work and hold the global lock like requests do. Do it when jobs wait on the default queue: in the console, `SolidQueue::ReadyExecution.group(:queue_name).count` shows how many are waiting on each queue.
- Raise `EVALUATION_THREADS` when fleet-wide runs after advisory imports take too long: re-matching costs about 10 ms a host, and the batches of one run spread over the threads. A rule change costs well under a millisecond a host and gains little from more threads.
- Raise `JOB_REALTIME_THREADS` to 2 when the liveness evaluation takes more than a few seconds (it scans every active host, #192), so the lease and expiry jobs scheduled in the same minute do not wait behind it.
- Each is a whole number from 1 to 64; anything else stops the boot with a message naming the setting.

### Solid Queue in its own container: `FLEET_JOBS_CONTAINER`

Set the GitHub variable `FLEET_JOBS_CONTAINER` to `true`. The deploy then starts the app without jobs, waits until it has migrated the databases, and starts a second container, `fleet-cmdb-jobs`, from the same image with the same settings and storage volume, running `bin/jobs`. It has no port. Unset or `false` goes back to one container, and the next deploy removes `fleet-cmdb-jobs`.

On one VM the two containers share the same cores, so this alone adds no capacity. What it gives:

- Jobs can be held to fewer cores than requests: `docker update --cpus 1 fleet-cmdb-jobs` keeps a fleet-wide matching run from taking cores the agents' requests need (until the next deploy, which recreates the container).
- Each has its own log (`docker logs fleet-cmdb-jobs`) and its own restart.
- It is the shape the next step needs, where jobs run on their own VM.

`/health` and the dashboard read job state from the queue database, so they work the same either way.

### Connection budget

Each process opens at most its pool to each database it uses, and the pool in `config/database.yml` follows the thread counts: the largest of `RAILS_MAX_THREADS`, `JOB_THREADS`, `JOB_REALTIME_THREADS`, and `EVALUATION_THREADS`, plus 2 (Solid Queue's polling and heartbeat). Call it P: 5 with the defaults. For planning, count each database as the threads in that process that use it, but never more than P:

| Process | Primary | Cache | Queue | Cable | With the defaults |
|---|---|---|---|---|---|
| Each Puma process (`WEB_CONCURRENCY`) | P: request threads, plus Action Cable's 4 worker threads and its event loop, which check operator sessions | `RAILS_MAX_THREADS` (the enrollment, onboarding, and download rate limits; agent requests no longer use it, #191) | `RAILS_MAX_THREADS` (enqueues) | 2 (Solid Cable's listener) | 5 + 3 + 3 + 2 = 13 |
| Each worker process for every queue (`JOB_CONCURRENCY`) | `JOB_THREADS` | `JOB_THREADS` | `JOB_THREADS` + 2 | `JOB_THREADS` | 3 + 3 + 5 + 3 = 14 |
| The realtime worker | `JOB_REALTIME_THREADS` | `JOB_REALTIME_THREADS` | `JOB_REALTIME_THREADS` + 2 | `JOB_REALTIME_THREADS` | 1 + 1 + 3 + 1 = 6 |
| The evaluation worker (#197) | `EVALUATION_THREADS` | `EVALUATION_THREADS` | `EVALUATION_THREADS` + 2 | `EVALUATION_THREADS` | 2 + 2 + 4 + 2 = 10 |
| Scheduler | | | P: the five every-minute tasks fire together, each on its own thread, beside its heartbeat | | 5 |
| Dispatcher | | | 3: polling, maintenance, heartbeat | | 3 |
| Supervisor | | | 1 | | 1 |
| Margin: backups, a console, the restore drill | | | | | 5 |

Total = `WEB_CONCURRENCY` x 13 + `JOB_CONCURRENCY` x 14 + 30 with the default threads. The hard ceiling, every process at its pool on every database it uses, is (`WEB_CONCURRENCY` + `JOB_CONCURRENCY` + 2) x 4P + 3P + 5 (100 with the defaults); real use stays well below it. Compare the plan with PostgreSQL's `max_connections` (default 100, of which 3 are kept for superusers), counting any other application on the same PostgreSQL server:

| Agents | `WEB_CONCURRENCY` | `JOB_CONCURRENCY` | Planned connections | Default `max_connections` 100 |
|---|---|---|---|---|
| Up to 2,000 | 1 | 1 | 57 | fits |
| 5,000 | 3 | 1 | 83 | fits |
| 10,000 | 5 | 1 | 109 | no: raise it |
| 10,000 | 5 | 2 | 123 | no: raise it |

Measured peaks (most connections seen per database while the mix load ran with three long jobs, 2 CPUs):

| | Primary | Cache | Queue | Cable | Total |
|---|---|---|---|---|---|
| One Puma process, jobs inside it, before S-7 | 8 | 4 | 13 | 1 | 26 |
| One Puma process, jobs inside it (default) | 9 | 4 | 14 to 15 | 2 to 3 | 30 to 31 |
| Two Puma processes, jobs inside | 11 | 8 | 17 | 1 | 37 |
| One Puma process, jobs in their own process | 7 | 4 | 14 | 2 | 27 |

The plan sits above the peaks because a pool is a ceiling: connections open only when a thread needs one, and stay open while it is idle.

When the plan passes about 90:

- **Raise `max_connections`** in the PostgreSQL container (provisioned outside this project) to the plan plus headroom, for example `ALTER SYSTEM SET max_connections = 200;`, and restart PostgreSQL. Each connection is a server process with its own memory, so check the database VM's memory after the change.
- **Or move the cache and cable databases** to another PostgreSQL server with `CACHE_DATABASE_URL` and `CABLE_DATABASE_URL`. That takes their connections (up to half of the plan, a fifth of the measured peaks) off the main one. (Before #191 it also took a rate-limit write per agent request; the agent limits are now in each process's memory.) A URL without a user or password, such as `postgres://db2.example.lan/cmdb_production_cache` in `FLEET_EXTRA_SETTINGS`, keeps the role `cmdb` and `DATABASE_PASSWORD` from `config/database.yml`, so no secret goes into a variable.

Past about 200 connections, or with more than one app VM, use PgBouncer instead (below).

### Rate limits with several processes (#191)

The agent API's limits are counted in each Puma process's memory, with no database write per request: the per-credential limit (`FLEET_API_RATE_LIMIT_PER_MINUTE`, 120 a minute) and the per-address limit on failed authentication (`FLEET_API_FAILED_AUTH_LIMIT_PER_MINUTE`, 60 a minute). With `WEB_CONCURRENCY` processes, each new connection may land on any of them, so a client whose requests reach several processes can get up to that many times each limit; a restart resets the counters. That still stops a runaway agent, which is what the limit is for: a normal agent sends about 3 requests a minute. Each process keeps counts for at most `FLEET_API_RATE_LIMIT_MAX_CREDENTIALS` credentials (100,000 by default, about 26 MB, plus as many recently authenticated key ids): above that fleet size, raise it, or the least recently counted credentials lose their counts. Enrollment, onboarding, and release-download limits stay in the cache database, shared by every process ([configuration.md](configuration.md)).

## Step 2: up to about 100,000 agents (not built yet)

- **Separate API and dashboard nodes** behind a load balancer: about 20 API cores at a 300 s poll interval (2,100 requests a second). The host constraints already keep `/api/v1` on the agent hostname.
- **Rate limit at the edge** (proposed, #191). With many API processes on several nodes, the in-process limits allow a client the limit once per process. Put the limit that must hold in the load balancer or proxy in front of the agent hostname: per credential key id (the part of `Authorization: Bearer <key_id>.<secret>` before the dot; the key id is not secret) at about 120 a minute, and per source address for requests that end in `401`, at about 60 a minute. Keep the application's limits as the second layer. **Required with a load balancer:** set `FLEET_TRUSTED_PROXIES` to its address and have it overwrite `X-Forwarded-For` with the client's address. Otherwise every agent's address is the load balancer's, and the application's failed-authentication limit treats the whole fleet as one client: agents that authenticated in the last 15 minutes still pass, but a restarted process or a new agent would be refused while a hostile client keeps that address over the limit ([configuration.md](configuration.md)). The application cannot do this itself without a shared counter (Redis or Valkey `INCR` and `EXPIRE`), which would be a second required service; the edge already sees every request.
- **PgBouncer in transaction mode** between the app and PostgreSQL (below).
- **A read replica** for the dashboard and reports.
- **Jobs on their own VM**, from the jobs container above.

### PgBouncer in transaction mode

**When:** the connection plan passes what PostgreSQL handles well (a few hundred), or several app VMs share one database. In transaction mode each transaction borrows a server connection and returns it at commit, so hundreds of app threads share a few dozen PostgreSQL connections.

**How:**

1. Run PgBouncer on the database's Docker network with `pool_mode = transaction`, one pool for each of the four databases, `max_client_conn` at least the connection plan above, and `default_pool_size` per database to fit `max_connections` (for example 40 for the primary and 10 for each of the others).
2. Point the app's requests at it: the app container's database host to the PgBouncer container and its port (6432 by default). Today `FLEET_DB_HOST` and `PGPORT` are one setting for both containers, so this step needs a database host override for the jobs container alone (not built yet; see the caveat below). Do not point `FLEET_DB_HOST` at PgBouncer before that exists.
3. In `config/database.yml` (a code change, made with this step): `prepared_statements: false`, because a prepared statement belongs to one server connection, which the next transaction may not get. PgBouncer 1.21 and later can track prepared statements itself (`max_prepared_statements`), which lets Rails keep them; measure before relying on it.
4. **Migrations run once, on a direct connection.** Rails serialises migrations with a session-level advisory lock, which is not safe through transaction pooling, and turning it off (`advisory_locks: false`) is only safe when one process migrates. With several app nodes every container runs `db:prepare` from `bin/docker-entrypoint` on start, so this step also changes the deploy: run `bin/rails db:prepare` once as a one-off container whose `DATABASE_URL` (and the queue, cache, and cable URLs) go straight to PostgreSQL, with the advisory lock left on, and have the entrypoint skip `db:prepare` on the nodes behind PgBouncer (for example with a setting that only the one-off sets).

**What stays safe:** the app's advisory locks today are all transaction-level (`pg_advisory_xact_lock`, `pg_try_advisory_xact_lock`), and `lock_timeout` is set with `SET LOCAL`; both end with their transaction. Solid Queue claims jobs with `FOR UPDATE SKIP LOCKED` inside transactions, and Solid Cable and Solid Cache poll and write in ordinary statements.

**The caveat, from #186:** batching the liveness evaluation (#186) holds a session-level advisory lock (`pg_try_advisory_lock`) across its batches, so that runs never overlap. Behind a transaction-mode PgBouncer the lock and its unlock may run on different server connections, so a lock could stay held by a connection another client then uses. Before PgBouncer goes in, either keep the jobs on a direct connection to PostgreSQL, or replace the lock with a lease row (a row with an expiry, taken with `UPDATE ... WHERE expires_at < now()`). A direct connection for the jobs needs the jobs container to have its own database settings (its own `DATABASE_URL` and queue, cache, and cable URLs, or its own `PGHOST` and `PGPORT`), which `cd.yml` does not offer yet: both containers share one env file. Its connections are few, so they fit beside PgBouncer's pools easily.

## Step 3: up to a million agents (not built yet)

- 100 to 200 API cores after the request-cost work (#189, #191).
- A dedicated PostgreSQL primary for agent writes (about 20,000 requests a second).
- The history tables partitioned by time (#195).
- Report ingestion behind a queue: accept, store the body, process it in a job, so a surge after an outage cannot use up the database's connections (#200 for agent-side spreading).

Re-measure each step with `bin/benchmark` before taking the next.
