# Scaling the server

How to size the server past the homelab, and the steps after that. The defaults are right for one VM with a few hundred agents; nothing here is needed below about 2,000. The capacity figures come from the scale benchmark (`bin/benchmark`, [benchmark.md](benchmark.md), from #188); re-measure with it after each step (#198, [ADR 0025](../decisions/0025-first-scale-step.md) for step 1, [ADR 0031](../decisions/0031-second-scale-step-readiness.md) for the settings steps 2 and 3 use).

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

Off by default. Set it to 2 (one less than `RAILS_MAX_THREADS`) once one process serves thousands of agents: a report that arrives while 2 are in flight in that process gets `503 overloaded` with `Retry-After` (30 to 45 s, `FLEET_REPORT_RETRY_AFTER_SECONDS`), so one thread is always free for heartbeats and hosts never go offline because of a report surge. The agent keeps the report and comes back after `Retry-After` (#200). A shed request costs no authentication and no database work, and an address over the failed-authentication limit never takes a slot. It is not free, though: by the time it is shed, Puma has read the body and the request guard (`AgentApiRequestGuard`) has copied it, up to 4 MiB for package and config reports, and the request has been routed. So size `FLEET_REPORT_MAX_IN_FLIGHT` against report CPU and database time, not against upload bandwidth or memory, which shedding does not save (review of #221). Watch the log for `[agent_api] shed`: steady shedding means the process count is too low, not a fault. Leave it off for `bin/simulate-fleet --load-check`, which sends 16 requests at once on purpose.

### Job workers: `JOB_THREADS`, `JOB_CONCURRENCY`, `JOB_REALTIME_THREADS`, `EVALUATION_THREADS`

- Raise `JOB_CONCURRENCY` (processes) before `JOB_THREADS` (threads in each): the long jobs (advisory refresh and import, per-host matching) are Ruby work and hold the global lock like requests do. Do it when jobs wait on the default queue: in the console, `SolidQueue::ReadyExecution.group(:queue_name).count` shows how many are waiting on each queue.
- Raise `EVALUATION_THREADS` when fleet-wide runs after advisory imports take too long: re-matching costs about 10 ms a host, and the batches of one run spread over the threads. A rule change costs well under a millisecond a host and gains little from more threads.
- Raise `JOB_REALTIME_THREADS` to 2 when the liveness evaluation takes more than a few seconds (it reads every host's narrow `host_liveness` row each minute, #192), so the lease and expiry jobs scheduled in the same minute do not wait behind it.
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

## Step 2: up to about 100,000 agents

The application side is built (ADR 0031, #198). Each part is an optional setting, off by default; the homelab sets none of them. The deployment itself is not built yet: running PgBouncer, a replica, a load balancer, and more than one VM, and the changes `cd.yml` needs for that (it deploys one VM).

- **Separate API and dashboard nodes** behind a load balancer (`FLEET_NODE_ROLE`, below): about 20 API cores at a 300 s poll interval (2,100 requests a second). The host constraints already keep `/api/v1` on the agent hostname.
- **Rate limit at the edge** (proposed, #191). With many API processes on several nodes, the in-process limits allow a client the limit once per process. Put the limit that must hold in the load balancer or proxy in front of the agent hostname: per credential key id (the part of `Authorization: Bearer <key_id>.<secret>` before the dot; the key id is not secret) at about 120 a minute, and per source address for requests that end in `401`, at about 60 a minute. Keep the application's limits as the second layer. **Required with a load balancer:** set `FLEET_TRUSTED_PROXIES` to its address and have it overwrite `X-Forwarded-For` with the client's address. Otherwise every agent's address is the load balancer's, and the application's failed-authentication limit treats the whole fleet as one client: agents that authenticated in the last 15 minutes still pass, but a restarted process or a new agent would be refused while a hostile client keeps that address over the limit ([configuration.md](configuration.md)). The application cannot do this itself without a shared counter (Redis or Valkey `INCR` and `EXPIRE`), which would be a second required service; the edge already sees every request. **What the edge must answer (#223):** for agents to wait out its limit, a refused request gets status `429`, a `Retry-After` header in whole seconds (at most 900; the agent honours at most 15 minutes), and a JSON body whose `error.code` is `rate_limited`, for example `{"error":{"code":"rate_limited","message":"Too many requests. Retry later."}}`. Off-the-shelf limiters (nginx `limit_req`, HAProxy, CDN rate-limit rules) send their own page by default, so set a custom error response. Any other `429` is treated as a transient failure: the agent ignores its `Retry-After`, retries with its normal backoff (about 5 s at first, doubling, up to 5 minutes, spread at random), and logs `not the fleet server's own rate limit`. The limit still holds either way; only the custom answer lets agents back off for as long as the edge asks.
- **PgBouncer in transaction mode** between the app and PostgreSQL (`FLEET_DB_POOLER`, `DIRECT_DATABASE_URL`, below).
- **A read replica** for the dashboard and reports (`REPLICA_DATABASE_URL`, below).
- **Jobs on their own VM**, from the jobs container above.

### PgBouncer in transaction mode: `FLEET_DB_POOLER`, `DIRECT_DATABASE_URL`

**When:** the connection plan passes what PostgreSQL handles well (a few hundred), or several app VMs share one database. In transaction mode each transaction borrows a server connection and returns it at commit, so hundreds of app threads share a few dozen PostgreSQL connections.

**What the app does with `FLEET_DB_POOLER=transaction`:**

- **No prepared statements** on the pooled databases (primary, cache, queue, cable, and the replica): a prepared statement belongs to one server connection, which the next transaction may not get. Without this setting, through PgBouncer with `max_prepared_statements = 0`, 75 of 480 queries from 8 threads failed (`prepared statement "a2" does not exist`, `prepared statement "a1" already exists`); with it, none did.
- **No migration advisory lock** on the pooled databases (`advisory_locks: false`): Rails takes a session-level lock around migrations, and its unlock could land on another server connection. So no migration runs through the pooler: every `db:migrate`, `db:prepare`, `db:setup`, `db:rollback`, and `db:schema:load` stops when `FLEET_DB_POOLER=transaction` is set (`lib/tasks/migrations.rake`), and the entrypoint refuses to start a server with the pooler set unless `FLEET_DB_PREPARE=false`. Migrations run once per deploy in a one-off container on direct connections, with the lock (step 3 below), as [ADR 0025](../decisions/0025-first-scale-step.md) planned.
- **The two session-level advisory locks go to the direct connection.** `DIRECT_DATABASE_URL` is the primary database without the pooler; the boot stops if the pooler is set without it. `SessionLock` takes these locks on it:
  - the liveness evaluation's (`Liveness.evaluate!`, #186), which keeps runs from overlapping across its batches;
  - a rollout stage prepare's (`Rollouts`, review of #215), which keeps a 1% stage from opening at 2%.

  The work under the lock still runs on the pooled connection; the direct one only holds the lock, idle meanwhile. So before each batch, and before a rollout prepare re-times a stage, the run checks that the lock's server process is the same one (Active Record reopens a lost connection without a word, which would have released the lock), and stops if not: the liveness run raises, and the next minute's run carries on; a rollout prepare rolls back its current batch and stops, and the next prepare carries on from the database's count, so a stage never gets more than its share. Unset, these locks use the primary's own connection with exactly the statements they ran before #198: no check, and no extra statement a batch (ADR 0031).

  The processes that take these locks, and so open a direct connection, are the jobs (the liveness run, and a rollout's automatic advance) and the dashboard: starting a rollout and an operator's Advance prepare the stage inside the request. So dashboard nodes need a route to the primary itself, not only to PgBouncer. Agent API requests never take one; API nodes need `DIRECT_DATABASE_URL` set with the pooler (the boot checks it) but open no direct connection.
- **Everything else is safe through the pooler,** and was checked: every other advisory lock is transaction-level (`pg_advisory_xact_lock`: advisory imports and manual refreshes, Debian triage, release imports, onboarding, rule writes, task settings, pending advisory uploads); `lock_timeout` is set with `SET LOCAL` or `set_config(..., true)` (live refresh, advisory imports); `SET TRANSACTION READ ONLY` runs inside its transaction (CIS dry runs and rule import plans); Debian triage's temporary table is `ON COMMIT DROP`, inside its transaction; the heartbeat directives' query is marked `preparable: true`, which Rails ignores with prepared statements off. Solid Queue claims jobs with `FOR UPDATE SKIP LOCKED` inside transactions and takes no advisory lock, so it needs no direct connection. Solid Cable polls its table and uses no `LISTEN` or `NOTIFY` (Action Cable's PostgreSQL adapter, which does, is not used). Solid Cache runs plain statements. The session settings Rails makes on connect (`IntervalStyle`, `TimeZone`, `standard_conforming_strings`) are ones PgBouncer tracks and replays for each client (PgBouncer 1.20 and later; `IntervalStyle` through `track_extra_parameters`, whose default includes it). Rails also sets `client_min_messages`, which PgBouncer does not track, but every client sets the same value (`warning`), so every server connection has it. Measured: 400 transactions from 8 threads over 2 server connections all saw `iso_8601`, `UTC`, `on`, and `warning`.

**How:**

1. Run PgBouncer on the database's network with `pool_mode = transaction` and one pool for each of the four databases (and one for the replica, if it goes through PgBouncer too). For example, with the plan below:

   ```ini
   [databases]
   cmdb_production       = host=db.example.lan dbname=cmdb_production       pool_size=40
   cmdb_production_queue = host=db.example.lan dbname=cmdb_production_queue pool_size=20
   cmdb_production_cache = host=db.example.lan dbname=cmdb_production_cache pool_size=10
   cmdb_production_cable = host=db.example.lan dbname=cmdb_production_cable pool_size=10

   [pgbouncer]
   ; The app network's address, not 0.0.0.0 (example: 198.51.100.10).
   listen_addr = 198.51.100.10
   listen_port = 6432
   pool_mode = transaction
   max_client_conn = 1000
   auth_type = scram-sha-256
   ; One line per role, with its SCRAM secret copied from PostgreSQL (below), so no password is stored in clear.
   auth_file = /etc/pgbouncer/userlist.txt
   ; Rails keeps no prepared statements with FLEET_DB_POOLER=transaction, so none to track.
   max_prepared_statements = 0
   ; The default; listed because IntervalStyle must be replayed for each client (Rails sets iso_8601).
   track_extra_parameters = IntervalStyle
   ```

   Fill `userlist.txt` with the role's SCRAM secret, read as a superuser on the primary: `SELECT format('"%s" "%s"', rolname, rolpassword) FROM pg_authid WHERE rolname = 'cmdb';` gives the whole line. Refresh it whenever `DATABASE_PASSWORD` changes. PgBouncer's `auth_query`, which looks the secret up at login, avoids that copy but needs a lookup function and role on the primary; either works.

2. Point the app's four database URLs at PgBouncer (`DATABASE_URL=postgres://pgbouncer.example.lan:6432/cmdb_production`, and `QUEUE_`, `CACHE_`, `CABLE_DATABASE_URL` the same way), set `FLEET_DB_POOLER=transaction`, and set `DIRECT_DATABASE_URL=postgres://db.example.lan/cmdb_production`. A URL without a user or password keeps the role `cmdb` and `DATABASE_PASSWORD` from `config/database.yml`, so no secret goes into a variable.
3. **Migrate once per deploy, in a one-off container on direct connections.** No server node migrates: every node behind the pooler sets `FLEET_DB_PREPARE=false` (the entrypoint refuses to start without it), and any migration through the pooler stops. Before the nodes start, run the image once with its four database URLs straight to PostgreSQL and the pooler unset, so Rails' migration lock is on:

   ```sh
   docker run --rm --env-file fleet-cmdb.env --network "$FLEET_DB_NETWORK" \
     -e FLEET_DB_POOLER= -e FLEET_DB_PREPARE= \
     -e DATABASE_URL=postgres://db.example.lan/cmdb_production \
     -e QUEUE_DATABASE_URL=postgres://db.example.lan/cmdb_production_queue \
     -e CACHE_DATABASE_URL=postgres://db.example.lan/cmdb_production_cache \
     -e CABLE_DATABASE_URL=postgres://db.example.lan/cmdb_production_cable \
     "fleet-cmdb:$sha" ./bin/rails db:prepare
   ```

   The one migrating container is that one-off, so nothing has to choose a node. It uses the deploy's env file and runs on the database's network, from the same image (`fleet-cmdb:$sha`, as `cd.yml` names it) the nodes will run. Two of them by mistake would still be safe, because Rails' lock is on. The nodes start after it succeeds. The deploy workflow does not run this yet (`cd.yml` deploys one VM); until it does, run it by hand before starting the nodes.

Measured with this repository's PgBouncer test (PgBouncer 1.22 in transaction mode, `pool_size=2` for the primary, one 2-CPU machine shared with PostgreSQL and other work, a 3,000-host seed, `bin/benchmark load --kind mix --threads 8 --duration 30`, one Puma process with jobs inside): 124.5 requests a second through PgBouncer and 173.4 straight to PostgreSQL, every request `200` both ways. Twenty liveness runs, four at once, through the pooler made 6,002 transitions and left no advisory lock held. On one machine PgBouncer only adds a hop, two server connections, and statements parsed each time. It pays off when many app processes on several VMs share one PostgreSQL. Measure on the real topology before relying on it (below).

**The hazard it avoids, measured:** the old way through the pooler, a liveness lock taken on one server connection and released from another (`pg_advisory_unlock` returned false) stayed held by that server connection after the client process had exited. Every later liveness run, from any process, was then refused until that server connection ended.

### Read replica: `REPLICA_DATABASE_URL`, `FLEET_REPLICA_MAX_WAIT_MS`, `FLEET_REPLICA_SKIP_SECONDS`, `FLEET_REPLICA_CONNECT_TIMEOUT_SECONDS`

**When:** dashboard pages over a large fleet take database time the agents' writes need. The fleet list and compliance pages read every host's summary row. A streaming replica of the primary takes that load.

**What reads it:** only these pages, on GET (each controller names them with `reads_from_replica`):

| Page | Action |
|---|---|
| Fleet list | `hosts#index` |
| Compliance | `compliance#index` |
| Audit log | `audit_entries#index` |
| A host's Configuration tab and config compare | `host_configs#show`, `#compare` |
| A host's Packages tab and package compare | `host_packages#show`, `#compare` |
| A host's Vulnerabilities tab and package page | `host_vulnerabilities#show`, `#package` |
| A host's Tasks tab | `host_tasks#show` |

The operator's session check, which records activity (a write), runs first, on the primary. Nothing else reads the replica: no agent API path, no write, nothing that checks or takes a second factor (step-up), no confirmation page. The task list and a task's page stay on the primary because they show whether the operator's second factor is recent, and that check takes a row lock. The suite runs every listed page on the reading role with writes refused, so an Active Record write or a row lock there fails the test, which is how the task list was found. A write hidden inside a `SELECT` (such as `SELECT nextval(...)`) or a `WITH` statement is not caught that way, because Rails treats those as reads; a real standby refuses it, and the page then fails over to the primary as below. A standby smoke test in CI would catch it earlier (not built; see ADR 0031).

**Lag:** a page reads the replica only once the replica has replayed everything the primary had written when the page started. It reads the primary's WAL position (`pg_current_wal_lsn()`) and waits until the replica's replay position (`pg_last_wal_replay_lsn()`) reaches it, at most `FLEET_REPLICA_MAX_WAIT_MS` (100 ms). Otherwise it reads the primary and logs `[replica] not caught up within 100 ms; this page reads the primary`. So no page shows older data than the primary would: an operator's own change, an agent's report, and a live refresh, which is sent after a change commits, all show at once, and there is no "sticky primary" delay to tune. This assumes `synchronous_commit` is on (the default) on the primary. **A server that is not in recovery is never read as a replica:** after a failover or promotion, or with the URL naming the wrong server, it is skipped and logged (`[replica] the replica server is not in recovery (promoted, or not a replica)`). Only the test environment, whose replica is the test database, allows it. A replica that cannot be reached (within `FLEET_REPLICA_CONNECT_TIMEOUT_SECONDS`, 2 s), or fails while a page reads it (a lost connection, or a query cancelled by a recovery conflict), is skipped for `FLEET_REPLICA_SKIP_SECONDS` (30 s), and pages read the primary meanwhile; the log names the error (`[replica] ActiveRecord::ConnectionFailed: ...; pages read the primary for 30 seconds`). The page that hit the failure runs again on the primary and answers normally. An error from the primary's own query is not blamed on the replica. Each page costs two small extra statements: one on the primary and one on the replica.

**How:** set `REPLICA_DATABASE_URL=postgres://replica.example.lan/cmdb_production` on the dashboard nodes. The replica gets its own pool of the same size in each process. It needs no setting on API or jobs nodes, which never read it.

### Node roles: `FLEET_NODE_ROLE`, `FLEET_DB_PREPARE`

The same image runs as any kind of node:

| | `FLEET_NODE_ROLE` | Serves | Jobs | Needs |
|---|---|---|---|---|
| Agent API node | `agent_api` | `/api/v1`, `/up`, `/health` on the agent hostname; nothing on the dashboard hostname | none: leave `SOLID_QUEUE_IN_PUMA` unset | primary (or PgBouncer), queue (enqueues), cache (enrollment, onboarding, and download rate limits), the releases directory; `FLEET_REPORT_MAX_IN_FLIGHT` set; `DIRECT_DATABASE_URL` set with the pooler, though it opens no direct connection |
| Dashboard node | `dashboard` | the dashboard, sign-in, and Action Cable on the dashboard hostname; only `/up` and `/health` on the agent hostname | none | primary, queue, cache, cable (each process's Solid Cable listener delivers live refreshes), the replica if any, the releases directory (uploads, the Agents page); with the pooler, a route to the primary itself for the direct connection (rollout start and Advance) |
| Jobs node | either, with no published port | nothing | `bin/jobs` (the jobs container), or `SOLID_QUEUE_IN_PUMA=1` on one node | all four databases, the direct database with a pooler, the releases directory (imports) |
| Homelab | `all` (default) | both hostnames | inside Puma | as today |

- A request for a hostname the node does not serve gets an empty 404, so a load balancer that sends it to the wrong pool shows up at once. Point the load balancer's health check at `/up` with the agent hostname or `localhost` as the `Host`: those are the names that serve it.
- Action Cable runs only where a page subscribes, so an API node opens no cable connections. Sign-out disconnects a session's live pages on every dashboard node through Solid Cable.
- Sessions are in the signed cookie, so any dashboard node serves any operator; every node needs the same `SECRET_KEY_BASE` and `FLEET_ENCRYPTION_KEY`.
- More than one Solid Queue scheduler is safe (Solid Queue keeps each recurring run once), but one jobs node is enough here.
- **Shared files:** release binaries (`FLEET_RELEASES_DIR`) and the backup status file (`FLEET_BACKUP_STATUS_FILE`) are files in the storage volume. The dashboard and jobs write release binaries (uploads and imports), API nodes serve them, and `/health` checks them on every node. With nodes on several VMs, mount the same storage there on each, or keep one copy per node by importing on each. Which of these to choose is open (ADR 0031).
- `FLEET_DB_PREPARE=false` skips the entrypoint's `db:prepare`. With several nodes, migrate with the one-off container above and set it on every node; behind the pooler that is required. Without the pooler, leaving it on one node also works, since Rails' lock keeps two from migrating at once, but a node that loses that race exits and restarts.

### Connection budget for step 2

Two budgets now: client connections to PgBouncer, which are cheap, and server connections from PgBouncer to PostgreSQL, which are what `max_connections` counts. Per process the client side is as in step 1 (13 for each Puma process, 39 for one jobs node with the default threads). The direct connection is one per process that takes a lock: the jobs worker that runs liveness, and any jobs or dashboard process that has prepared a rollout stage. It stays open, idle in its pool, after the lock is released, and the every-minute liveness run keeps the jobs one open for good. That is about 10 standing connections in the example below, whatever the agent count.

An example for 100,000 agents at a 300 s poll interval (2,100 requests a second): four API nodes of 5 Puma processes, two dashboard nodes of 2, one jobs node.

| | Client connections | Server connections |
|---|---|---|
| API processes (20 x 13) | 260 to PgBouncer | |
| Dashboard processes (4 x 13) | 52 to PgBouncer; up to 4 x P = 20 to the replica | |
| Jobs node (step 1's 39) | 39 to PgBouncer | |
| Direct connections | 1 a jobs worker plus 1 a dashboard process that has prepared a stage, kept open: about 10 | about 10, to PostgreSQL |
| PgBouncer's pools (`pool_size`) | `max_client_conn` 1,000 | 40 + 20 + 10 + 10 = 80, to PostgreSQL |
| Margin: backups, a console, the one-off migration | | 10 |
| **PostgreSQL primary** | | **about 100**: the default `max_connections` with a little headroom; set 150 |

The primary's pool of 40 assumes each agent request holds a server connection for about 10 ms. That is 21 busy at 2,100 requests a second, nearly half the pool. Check it with `SHOW POOLS;` in PgBouncer's admin console: `cl_waiting` above 0 for long, or a growing `maxwait`, means the pool is too small. The replica's connections are on the replica server, not the primary.

### What to measure with `bin/benchmark` at step 2

- **One API node through PgBouncer:** `bin/benchmark load --kind mix` against one Puma process, through PgBouncer and straight to PostgreSQL, on the real VMs. Requests a second per process is the figure to scale the API core count from (110 on the reference machine, straight). Watch `SHOW POOLS;` meanwhile.
- **The cost of no prepared statements:** `bin/benchmark queries` with `FLEET_DB_POOLER=transaction` and the URLs through PgBouncer, against the same run without. Statements and rows per request must not change; SQL time a request may rise a little, because each statement is parsed again.
- **Jobs:** `bin/benchmark jobs` for the liveness evaluation with `DIRECT_DATABASE_URL` set; it must cost the same as before, with one extra statement a batch (the lock check).
- **The replica:** `bin/benchmark explain` covers the fleet list, compliance, and audit log statements; on the replica, the same plans should hold. In production, count `[replica] not caught up` in the dashboard nodes' log against page views, and watch `pg_stat_replication.replay_lag` on the primary. A steady share of pages reading the primary means the replica lags more than `FLEET_REPLICA_MAX_WAIT_MS`.
- **The edge rate limit** and the load balancer: `bin/benchmark load` from more than one machine, so the limit sees more than one address.

## Step 3: up to a million agents (not built yet)

- 100 to 200 API cores after the request-cost work (#189, #191): 20 to 40 API nodes as above, with the same settings.
- A dedicated PostgreSQL primary for agent writes (about 20,000 requests a second). The replica and the dashboard nodes take the dashboard's reads off it (step 2).
- The history tables partitioned by time (#195).
- Report ingestion behind a queue: accept, store the body, process it in a job, so a surge after an outage cannot use up the database's connections (#200 for agent-side spreading).

**Connection budget for step 3 (an estimate, to be measured):** 200 API processes x 13 is 2,600 client connections. Several PgBouncer instances share them, each single-threaded: plan one per few thousand transactions a second, and measure it. At 20,000 requests a second and about 10 ms each, about 200 server connections are busy on the primary. So the primary's PgBouncer pools total about 250, and `max_connections` is about 300, sized against the database VM's memory. The direct connections stay about 10: the liveness run and the rollout prepares do not grow with the API nodes.

**What to measure at step 3:** `bin/benchmark load` against each kind of node as at step 2, plus a surge: every agent reporting at once after an outage (`--kind mix` with many threads from several machines), to size report load shedding (`FLEET_REPORT_MAX_IN_FLIGHT`) and the queued ingestion. Also `bin/benchmark jobs` for the liveness evaluation at a million hosts: it reads every host's narrow row each minute, so if a run takes more than a few seconds, raise `JOB_REALTIME_THREADS` (step 1).

Re-measure each step with `bin/benchmark` before taking the next.
