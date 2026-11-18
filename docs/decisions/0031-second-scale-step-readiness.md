# ADR 0031: Second scale step: optional pooler, direct connection, replica reads, and node roles

- Status: Accepted (approved by the owner, 2026-11-18)
- Decision issue: #198 (steps 2 and 3); the owner chose "app-side readiness only" on 2026-11-16 and decided the open questions of #237 on 2026-11-18
- Requirements: `NFR-3`, `FR-1.4`, `FR-S.2`, `NFR-4`
- Builds on: [ADR 0025](0025-first-scale-step.md) (the first step), and follows its plan that migrations run once on a direct connection. It departs from ADR 0025 and the #198 comment on one point, approved by the owner: the direct connection is not jobs-only (below).
- Known limits ([ADR 0019](0019-scale-direction.md)): "deployment on one machine" stays the default; this makes the next step possible by configuration.

## Context

Past about 10,000 agents, #198 plans PgBouncer in transaction mode, a read replica for the dashboard, and separate agent-API and dashboard nodes behind a load balancer. None of that could be switched on without code changes:

- Rails uses prepared statements, and a session-level lock around migrations.
- Three session-level advisory locks span several transactions: the liveness evaluation's (#186), a rollout stage prepare's (review of #215), and the partition maintenance run's (#195, #239).
- No page could read a replica.
- Every node served both hostnames.

The owner decided (2026-11-16) to build only what the app needs, as optional settings that are all off by default, so the homelab's one container and one PostgreSQL work as before with no new required service. Running PgBouncer, a replica, or more nodes stays a deployment step for later.

## Decision

- **`FLEET_DB_POOLER=transaction`** turns off prepared statements and Rails' migration advisory lock on the pooled databases (primary, cache, queue, cable, and the replica). Unset, nothing changes.
- **Migrations never run through the pooler** (ADR 0025's "migrations run once on a direct connection"). With the pooler set, every task that migrates or loads a schema stops, and the entrypoint refuses to start a server unless `FLEET_DB_PREPARE=false`. Migrations run once per deploy in a one-off container from the same image, with its database URLs straight to PostgreSQL and the pooler unset, so Rails' lock is on. That one-off is the one migrating container, so no node has to be chosen. Rejected: migrating from a serving node over `DIRECT_DATABASE_URL`, which names only the primary, not the queue, cache, and cable databases. The owner wants the one-off in `cd.yml`, off unless `FLEET_DB_POOLER` is set; that is a follow-up to #237.
- **`DIRECT_DATABASE_URL`**, required with the pooler: the primary without the pooler. `SessionLock` takes the three session-level advisory locks on it: liveness, rollout prepare, and partition maintenance. The work under each lock still runs on the pooled connection.
  - Before each batch, or each table for partition maintenance, the run checks the lock's server process id. A lost and silently reopened lock connection then stops the run before its next write.
  - The check runs on every path, the homelab's included, which costs one small statement a batch (the owner's decision, 2026-11-18). On the homelab's single connection, Active Record reopens a dropped connection at the next transaction without the lock.
  - Every lock statement runs uncached. Inside a request or a job the query cache is on, and would otherwise answer the check with the first process id.
  - A stopped liveness run is caught up by the next minute's.
  - A stopped prepare raises `Rollouts::Interrupted`. A start rolls back and says so, an operator's Advance says the stage was not opened, and the automatic advance leaves it to the backstop.
  - Without the setting, the locks use the primary's own connection.
  - Every other advisory lock in the app is transaction-level and stays where it is. Solid Queue (`FOR UPDATE SKIP LOCKED` in transactions) and Solid Cable (it polls a table, with no `LISTEN`) need no direct connection.
- **`REPLICA_DATABASE_URL`**: a streaming replica. `ApplicationRecord` gets a reading role. Only the dashboard and report pages named with `reads_from_replica` use it, on GET or HEAD: the fleet list, compliance, the audit log, and a host's Configuration, Packages, Vulnerabilities, and Tasks tabs. The owner approved this list.
  - **Caught up first.** A page reads the replica only once it has replayed the primary's WAL position read at the page's start. It waits at most `FLEET_REPLICA_MAX_WAIT_MS` (100 ms), counted from the replica's first answer, with uncached polls; otherwise it reads the primary. So no page shows older data than the primary would, and read-after-write needs no stickiness.
  - **Never a server that is not in recovery** (a promoted ex-replica, or the wrong URL). Only the test environment allows it, because its replica is the test database (`config.x.replica_may_be_primary`: false in `config/application.rb`, true in `test.rb`, compared with `== true`).
  - **A replica that fails mid-page shows a plain error page**, and the page is not run again (the owner's decision, 2026-11-18). A connection-level failure or a recovery conflict marks the replica down for `FLEET_REPLICA_SKIP_SECONDS` (30), so the next load reads the primary. The same happens when the replica fails its check. A cancelled query (a `statement_timeout` on the replica, or `pg_cancel_backend`) fails the page but leaves the replica in use, so one slow page does not send every page to the primary. An error from the primary is never blamed on the replica. The connect timeout is `FLEET_REPLICA_CONNECT_TIMEOUT_SECONDS` (2). The owner kept the three defaults.
  - **Writes are refused on the reading role**, and the test suite runs every listed page on it. That catches Active Record writes and row locks; a write inside a `SELECT` or `WITH` is caught only by a real standby.
  - **Never on the replica:** agent API paths, every write, step-up (second-factor) checks, and the task list and task pages, which show step-up state.
- **`FLEET_NODE_ROLE`**: `all` (default), `agent_api` (refuses the dashboard hostname), or `dashboard` (refuses `/api` on the agent hostname, keeps the health paths). Where jobs run stays as today (`SOLID_QUEUE_IN_PUMA`, `bin/jobs`).
- **`FLEET_DB_PREPARE=false`** makes the entrypoint skip `db:prepare`, so with several nodes, or behind the pooler, the one-off container migrates and the nodes do not.
- Rejected: replacing the session locks with lease rows. That changes the schema for a case a direct connection already covers.
- Rejected: Rails' automatic role switching (`DatabaseSelector`). It routes every GET, including agent API reads and the pages that check a second factor, and guards read-after-write only by a time delay after the session's own writes.
- Rejected: a replica for the agent API's reads. Every agent request writes, and reads under the host lock.
- Rejected (by the owner): running a page again on the primary when its replica fails mid-page. That would require every replica page to be safe to run twice.

## Consequences

- With nothing set, database.yml has the same four databases, no page switches role, every node serves both hostnames, and the entrypoint migrates. The session locks run one more small statement a batch than before #198 (the per-batch check), the one change on the homelab path.
- The direct connection is opened by the jobs and by dashboard processes, because starting a rollout and an operator's Advance prepare the stage inside the request (kept by the owner). So dashboard nodes need a network route to the primary itself, not only to the pooler; the deployment step records that in the network design and threat model row B5, with PgBouncer's copy of the role's SCRAM secret and the replica.
- Each replica page costs two small statements: the primary's WAL position and the replica's check. When the replica lags, the page also waits up to the configured time before reading the primary.
- Known limits, recorded in #198's remaining steps (the owner's decision, 2026-11-18; no new issues):
  - Release binaries and the backup status file are on the storage volume, so nodes on separate VMs need shared storage, or another home for release binaries.
  - At step 3 write rates, replay can fall behind the primary's current position during WAL bursts, so pages return to the primary just when it is busiest. A per-session "last write" position would avoid that.
  - No CI job runs the listed pages against a real standby; reviewers did it by hand for #237.
  - Lease rows in place of the direct connection are not built.
- Running PgBouncer, the replica, the load balancer, and the deploy changes stay open in #198: the one-off migration in `cd.yml` is the first follow-up. So does step 3, queued ingestion.
