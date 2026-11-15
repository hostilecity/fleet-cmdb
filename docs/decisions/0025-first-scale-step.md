# ADR 0025: First scale step: process sizing, a realtime job queue, and an optional jobs container

- Status: Proposed (needs the owner's OK)
- Decision issue: #198 (and server finding S-7 of the scale assessment)
- Requirements: `NFR-3`, `FR-1.4`, `NFR-4`
- Amends: [ADR 0023](0023-deploy-with-github-actions.md), which runs one container. One container stays the default.
- Known limits ([ADR 0019](0019-scale-direction.md)): "deployment on one machine" stays; this only documents and configures how far one machine goes.

## Context

One Puma process with 3 threads serves about 2,100 agents on the default intervals, and nothing documented the next step (#198). All jobs shared one queue with one worker of 3 threads, so three long jobs (an advisory refresh can download for 15 minutes, then import) held back the every-minute liveness, task-lease, and task-expiry jobs (S-7): measured, a liveness run waited 94 s. The database pool came from `RAILS_MAX_THREADS` alone, so raising the job threads could exhaust it.

## Decision

- **A `realtime` queue** for the jobs that run every minute (liveness, task leases, task expiry, rollout timeouts, report request expiry) and the live-refresh broadcasts, served by a worker of its own (`JOB_REALTIME_THREADS`, default 1). The worker for every queue (`JOB_THREADS`, default 3, in `JOB_CONCURRENCY` processes, default 1) takes realtime jobs too when it is free. Broadcasts have a lower priority than the every-minute jobs on that queue.
- **Thread and process counts are settings** (`RAILS_MAX_THREADS`, `WEB_CONCURRENCY`, `JOB_THREADS`, `JOB_CONCURRENCY`, `JOB_REALTIME_THREADS`), read in one place (`cmdb/lib/sizing/process_sizing.rb`). Each database pool is the largest thread count plus 2. A bad value stops the boot.
- **Jobs may run in their own container** when the deploy variable `FLEET_JOBS_CONTAINER` is `true`: `fleet-cmdb-jobs`, from the same image and settings, started after the app has migrated. Unset, everything stays in one container.
- **The sizing and the connection budget** are documented in `docs/operations/scaling.md`, with when and how to add PgBouncer in transaction mode and the later steps. PgBouncer itself is not built.
- Rejected: one worker reading `[realtime, default]` in order. Queue order decides which job a free thread takes next, but does not keep a thread free: three long default jobs still hold every thread.
- Rejected: a second required container by default. It adds no capacity on one VM and makes the homelab deploy larger.

## Consequences

- The default deploy gains one process (the realtime worker, about 55 MB) and about three database connections; nothing else changes for the homelab.
- A long job can no longer delay liveness or lease expiry. A long realtime job still can: realtime jobs must stay short, and the liveness evaluation's cost at scale is #192's.
- PgBouncer in transaction mode needs `prepared_statements: false`, migrations run once on a direct connection (with several app nodes the entrypoint must stop running `db:prepare` on each), and either a jobs-only direct database connection (not offered by `cd.yml` yet) or a lease row in place of the session-level liveness lock from #186. That is the next step's work.
