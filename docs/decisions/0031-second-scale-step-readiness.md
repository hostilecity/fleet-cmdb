# ADR 0031: Second scale step: optional pooler, direct connection, replica reads, and node roles

- Status: Proposed (needs the owner's OK)
- Decision issue: #198 (steps 2 and 3); the owner chose "app-side readiness only" on 2026-11-16
- Requirements: `NFR-3`, `FR-1.4`, `FR-S.2`, `NFR-4`
- Builds on: [ADR 0025](0025-first-scale-step.md) (the first step). Known limits ([ADR 0019](0019-scale-direction.md)): "deployment on one machine" stays the default; this makes the next step possible by configuration.

## Context

Past about 10,000 agents, #198 plans PgBouncer in transaction mode, a read replica for the dashboard, and separate agent-API and dashboard nodes behind a load balancer. None of that can be switched on today without code changes: Rails uses prepared statements and a session-level migration lock, two session-level advisory locks span several transactions (the liveness evaluation, #186, and a rollout stage prepare, review of #215), no page can read a replica, and every node serves both hostnames. The owner decided (2026-11-16) to build only what the app needs, as optional settings that are all off by default, so the homelab's one container and one PostgreSQL work exactly as before with no new required service. Running PgBouncer, a replica, or more nodes stays a deployment step for later.

## Decision

- **`FLEET_DB_POOLER=transaction`** turns off prepared statements and Rails' migration advisory lock on the pooled databases (primary, cache, queue, cable, and the replica). Unset, nothing changes.
- **`DIRECT_DATABASE_URL`**, required with the pooler: the primary without the pooler. `SessionLock` takes the two session-level advisory locks on it, and the work under the lock still runs on the pooled connection. The lock check between batches compares the server process id, so a lost and silently reopened lock connection stops the run. Unset, the locks use the primary's own connection, as before. Every other advisory lock in the app is transaction-level and stays where it is. Solid Queue (`FOR UPDATE SKIP LOCKED` in transactions) and Solid Cable (it polls a table; no `LISTEN`) need no direct connection. Action Cable's PostgreSQL adapter, the one that uses `LISTEN`, is not used.
- **`REPLICA_DATABASE_URL`**: a streaming replica. `ApplicationRecord` gets a reading role, and only the dashboard and report pages named with `reads_from_replica` use it: the fleet list, compliance, the audit log, and a host's Configuration, Packages, Vulnerabilities, and Tasks tabs (GET only). A page reads the replica only once it has replayed the primary's WAL position read at the page's start, waiting at most `FLEET_REPLICA_MAX_WAIT_MS` (100 ms); otherwise it reads the primary. So no page shows older data than the primary would, and read-after-write needs no stickiness. A failing replica is skipped for 30 s. Writes are refused on the reading role, and the test suite runs every listed page on it. Agent API paths, every write, step-up (second-factor) checks, and the task list and task pages, which show step-up state, never use it.
- **`FLEET_NODE_ROLE`**: `all` (default), `agent_api` (refuses the dashboard hostname), or `dashboard` (refuses `/api` on the agent hostname, keeps the health paths). Jobs placement stays as today (`SOLID_QUEUE_IN_PUMA`, `bin/jobs`).
- **`FLEET_DB_PREPARE=false`** makes the entrypoint skip `db:prepare`, so with several nodes, or behind the pooler (with no migration lock), one container runs migrations and the others do not.
- Rejected: replacing the session locks with lease rows. That changes the homelab's behaviour and schema for a case a direct connection already covers. A lease is still possible later if a pooler must carry everything.
- Rejected: Rails' automatic role switching (`DatabaseSelector`). It routes every GET, including agent API reads and the pages that check a second factor, and guards read-after-write only by a time delay after the session's own writes. It does nothing for an agent's write or a live refresh.
- Rejected: a replica for the agent API's reads. Every agent request writes, and reads under the host lock.

## Consequences

- The homelab is unchanged: with nothing set, database.yml has the same four databases, no page switches role, every node serves both hostnames, and the entrypoint migrates.
- Each replica page costs two small statements: the primary's WAL position and the replica's check. On a replica that lags, it also waits up to the configured time before reading the primary.
- Separate nodes still share the release binaries and the backup status file on the storage volume (`FLEET_RELEASES_DIR`, `FLEET_BACKUP_STATUS_FILE`). Splitting nodes across VMs needs shared storage, or another home for release binaries. That is a decision for the deployment step.
- Running PgBouncer, the replica, the load balancer, and the deploy changes (`cd.yml` still deploys one VM), plus step 3 (partitioning, #195; queued ingestion), stay open in #198.
