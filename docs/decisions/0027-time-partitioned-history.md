# ADR 0027: Time-partitioned history tables; retention drops whole partitions

- Status: Proposed (#195; needs the owner's OK)
- Decision issue: #195
- Requirements: `NFR-2`, `NFR-3`, `FR-S.3`, `FR-1.3`, `FR-2.2`; P1-S10 ([p1-operability.md](../backlog/specs/p1-operability.md))
- Extends: [ADR 0007](0007-snapshots-and-retention.md). Its rules stay: snapshots and status history are kept for the retention window, each host's newest snapshot and status change are always kept, and audit entries are never pruned. Only how pruning is done changes.
- Known limits ([ADR 0019](0019-scale-direction.md)): "one PostgreSQL database" stays. This removes the daily row-by-row prune from what that database must do.

## Context

`Retention` (`cmdb/app/services/retention.rb:47`) deletes expired rows in batches of 1,000 by id. For the tables that keep each host's newest row, every batch runs an `EXISTS` anti-join to skip it. Measured on the benchmark (#188) on a seed of 20,001 hosts (below): **975,041 expired rows took 23.1 s, 0.024 ms a row** (median of 3, rolled back). The assessment measured 0.03 ms a row on 100,000 hosts (P-13).

Per host and day on the default intervals the server writes 104 report receipts (96 inventory, 4 config, 4 package; kept 7 days with #187), plus snapshots on change, a status event per transition, and CIS result changes per changed result. At a million hosts the receipts alone are 104 million rows a day. At 0.024 ms a row that is **42 minutes of deletes every day**, before the vacuum and WAL that the deletes cause. Snapshots, events, and changes add to it. `audit_entries` is never pruned (FR-S.3) and grows with every agent update and task: about 2 entries a host for each agent release (`update.requested`, then its outcome), and about 4 for each task.

**How it was measured.** The benchmark from #188, merged locally only (`bin/benchmark seed --hosts 20000 --package-hosts 5000 --receipts 60 --audit-entries 10`, 2.9 GB, history spread over 1.2 windows). PostgreSQL 16 with default settings on 2 CPUs, shared with other agents' suites (load average 4 to 6), so times are rough; row counts are exact. The partitioning steps were run in SQL on the seeded tables. The prototype is not in this PR.

## Options considered

| Option | For | Against |
|---|---|---|
| **Native declarative partitioning, a small partition manager in the app** (chosen) | Built into PostgreSQL 11 and later. Nothing to install. Works on the homelab's existing container and on managed PostgreSQL. The app already knows each table's retention rule. | About 200 lines of app code to own and test. |
| Native partitioning, `pg_partman` for maintenance | Mature create-ahead and drop-behind. Available on the large managed services. | An extension the homelab's PostgreSQL container does not have: the official image does not ship it, and the container is provisioned outside this project. It cannot keep each host's newest row, so the app needs its own pass anyway. One more moving part to upgrade. |
| TimescaleDB hypertables | Automatic chunking, compression. | An extension with its own licence terms for some features, missing from many managed services; far more than this needs. |
| Keep deleting rows, tuned (bigger batches, keyset batches, more vacuum) | No schema change. | Cost stays linear in rows: still an hour a day at a million hosts, plus bloat. |
| Inheritance-based partitioning with triggers | Works on old PostgreSQL. | Superseded by declarative partitioning; slower inserts; more code. |
| Partitions, with each host's newest row kept by the current-state tables (#195's own proposal: `host_inventories`, `host_configs`, `host_package_sets` gain the newest snapshot's id, or hold the snapshot) | No `stored_at` column; partitions drop with nothing moved; history keyed on its real time. | The newest snapshot's row is still dropped, so every reader of history (the inventory, config, and package timelines and diffs, `CisResultHistory`, `PackageDiff.for`, `CisDryRun`, the restore check) must union a pseudo-snapshot built from the current-state row, with its own id. The current-state rows are rewritten on every report (`received_at`, `report_id`), so they would need a second copy of the snapshot's own fields. `cis_results.config_snapshot_id` would point at a dropped row for every host whose config has not changed for a window. Moving the newest rows forward keeps one place for history and leaves those readers as they are. |

## Decision

1. **Native range partitioning by time** for the tables that grow with the fleet and with time. Retention then **drops whole partitions** (one catalog operation each) instead of deleting rows.
2. **Which tables:**

   | Table | Partition key | Width | Each host's newest row kept | Dropped |
   |---|---|---|---|---|
   | `inventory_report_receipts`, `config_report_receipts`, `package_report_receipts` | `received_at` | 1 day | no | after the receipt window (7 days, #187) |
   | `inventory_snapshots`, `config_snapshots`, `package_snapshots` | `stored_at` (new) | 7 days | yes | after the retention window |
   | `host_status_events` | `stored_at` (new) | 7 days | yes | after the retention window |
   | `cis_result_changes` | `occurred_at` | 7 days | no | after the retention window |
   | `audit_entries` | `occurred_at` | 1 month | n/a | **never** (FR-S.3) |

   Above a 180-day retention window the 7-day tables use 30-day partitions, so a long window (the setting allows up to 3,650 days) never makes hundreds of partitions. A changed width applies to partitions created after the change; existing ones keep theirs.
3. **Not partitioned:** `tasks`, `task_batches`, and `task_late_results` stay as they are and are never deleted (P3-S02, P3-S07). Tasks grow with operator actions, at most 25 hosts a batch, not with the fleet's reporting. `tasks` is also updated in place through its lifecycle and has `uuid` unique on its own, which a partitioned table cannot enforce. `vulnerability_findings` (resolved rows), `report_requests`, and `advisory_refresh_attempts` keep row deletes: they are small, or current state that only some rows leave (and #196 reshapes findings).
4. **Keeping each host's newest row: move it forward.** A partition whose whole range is older than the window is retired in three steps, each its own transaction:
   1. **Move** each host's newest row in it, for every host with no row in any other partition, to the current partition by `UPDATE ... SET stored_at = now()`. PostgreSQL moves a row whose partition key changes to the partition it now belongs to, keeping its id (verified). This runs in batches of 1,000 rows, each a short transaction, so even the legacy partition (below), which may hold every host's newest row, never makes one large transaction (P1-S10's rule). A reader never sees a row twice.
   2. **Detach** the partition: a catalog change.
   3. **Drop** the detached table, after the detach has committed. It is no longer part of the parent, and with no foreign keys (below) the drop locks nothing else.

   `received_at` (or `occurred_at`) keeps its meaning; `stored_at` says "when this row was last stored". That is why these tables partition on a new `stored_at` and not on `received_at`: a kept row must move to a live partition without changing what it says. The anti-join now runs once per retired partition, over that partition only, not once per batch over the whole table.
5. **A default partition on every partitioned table except `audit_entries`**, normally empty, so a write never fails because a partition is missing: a heartbeat that changes liveness writes a status event, and it must not fail for a maintenance reason. The health endpoint (NFR-4) reports a non-empty default partition and fewer than two partitions created ahead. The manager repairs a non-empty default by moving its rows (a `DELETE` from the default and an `INSERT` into a new partition for their range, in one transaction).

   **`audit_entries` has no default partition: it fails closed.** Moving rows out of a default would be a `DELETE`, which its guard refuses (verified by the review), and the only other repair is to detach the default, which decision 7 forbids. So the manager creates audit partitions **3 months ahead**, the health endpoint is red under 2 months ahead, and if every warning were missed an audited action would fail rather than be recorded nowhere, which is the guarantee FR-S.3 wants.
6. **Partition maintenance is a job in the app, and it never waits for a lock.** `PartitionMaintenanceJob` runs **every hour** on the `default` queue (and once at boot, after `db:prepare`). It creates partitions ahead (3 days for daily tables, 3 weeks for weekly, 3 months for audit), then `Retention` retires what has expired. Creating a partition and a plain `DETACH` both take an `ACCESS EXCLUSIVE` lock on the parent for milliseconds once granted (measured), but must wait for every running query on it, and queries that arrive meanwhile queue behind them. So:
   - each DDL statement runs with **`lock_timeout = '150ms'`**, tried up to 3 times a run with a pause between, so a query on the parent waits at most 150 ms behind one attempt;
   - a run does no DDL while a backup is running (a `pg_dump` session in `pg_stat_activity`): the nightly dump (02:30 plus up to 10 minutes, `ops/backup/fleet-cmdb-backup.timer`) holds a lock on every table for as long as it runs, hours at scale, so every attempt would time out;
   - work that is due is not lost: the next hourly run tries again. The health endpoint warns when a partition has been due for retirement, or one ahead has been missing, for **3 days**.

   Retiring uses a plain `DETACH`: PostgreSQL refuses `DETACH ... CONCURRENTLY` when a default partition exists (verified).
7. **The audit log stays append-only and is never dropped.** The manager only creates audit partitions; it has no code path that detaches or drops one, and a spec proves it. An audit archive policy (detach and export old months) is a separate decision for the owner and would change FR-S.3.

## Data model

Primary keys on a partitioned table must include the partition key, and so must every unique constraint. Each table's key becomes `(id, <partition key>)`. Ids still come from the table's one sequence, so they stay unique in practice; a row moved forward keeps its id and is never in two partitions at once.

```sql
-- Snapshot and status-event tables (inventory shown; config, package, and host_status_events are alike)
CREATE TABLE inventory_snapshots (
  id           bigint NOT NULL DEFAULT nextval('inventory_snapshots_id_seq'),
  host_id      bigint NOT NULL,  -- no foreign key (see below)
  stable       jsonb NOT NULL,
  warnings     jsonb NOT NULL DEFAULT '[]',
  stable_hash  varchar(64) NOT NULL,
  report_id    uuid NOT NULL,
  collected_at timestamp NOT NULL,
  received_at  timestamp NOT NULL,
  stored_at    timestamp NOT NULL DEFAULT now(),  -- the partition key: when this row was (last) stored
  PRIMARY KEY (id, stored_at)
) PARTITION BY RANGE (stored_at);
CREATE INDEX ON inventory_snapshots (host_id, received_at);  -- created on every partition
CREATE INDEX ON inventory_snapshots (received_at);
CREATE TABLE inventory_snapshots_p20261116 PARTITION OF inventory_snapshots
  FOR VALUES FROM ('2026-11-16') TO ('2026-11-23');
CREATE TABLE inventory_snapshots_default PARTITION OF inventory_snapshots DEFAULT;

-- Receipts: no stored_at; the unique (host_id, report_id) becomes a plain index (see below)
CREATE TABLE inventory_report_receipts (
  id          bigint NOT NULL DEFAULT nextval('inventory_report_receipts_id_seq'),
  host_id     bigint NOT NULL,
  report_id   uuid NOT NULL,
  received_at timestamp NOT NULL,
  PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);
CREATE INDEX ON inventory_report_receipts (host_id, report_id);

-- Audit: monthly, never dropped
CREATE TABLE audit_entries ( ...as today..., PRIMARY KEY (id, occurred_at) ) PARTITION BY RANGE (occurred_at);
```

- **No foreign keys out of a partitioned table.** A foreign key on a partitioned table ties every partition operation to the table it references. Measured on PostgreSQL 16 with a key to `hosts`: creating a partition and a plain `DETACH` take `SHARE ROW EXCLUSIVE` on `hosts`, which blocks the `UPDATE hosts` that every heartbeat runs, and dropping the detached partition takes `ACCESS EXCLUSIVE` on `hosts`, which blocks every read of it. Without the key, the same three operations take no lock on `hosts` at all, and the drop takes none on the parent either (measured). This would happen daily on 3 tables and weekly on 5 more, on the table every agent request and page reads. So `host_id`, and `cis_result_changes`' `cis_rule_id` and `cis_rule_version_id`, become plain columns. What the keys checked still holds: hosts are never deleted (`hosts_no_delete`), every writer of these tables holds the host's row lock (`AgentHostLock`, `Liveness`), and no code path deletes a CIS rule or rule version (they are disabled and versioned). A nightly check (`partitions:check`) reports any row whose host or rule does not exist.
- **Foreign keys into a partitioned table** must go too. Today `cis_results.config_snapshot_id` and `cis_result_changes.config_snapshot_id` reference `config_snapshots` with `ON DELETE SET NULL`. A foreign key to a partitioned table must name its whole key `(id, stored_at)`, and PostgreSQL then refuses to detach or drop a partition that a row still references (both verified). They become **plain columns**: a reader treats an id with no snapshot as "no longer kept", as it treats NULL today (`CisResultHistory`). Moving the newest row forward keeps its id, so a host's current results still point at a snapshot that exists.
- **Unique `(host_id, report_id)` on receipts** cannot be enforced across partitions. Every recorder already takes the host's row lock first (`AgentHostLock`, for example `package_recorder.rb:26`), so duplicate detection becomes "is there a receipt for this host and report id" and then an insert, under that lock; `insert_all(unique_by:)` goes. The lookup probes each partition's `(host_id, report_id)` index: 0.31 ms over 16 partitions on the seed.
- **Rails.** Models of partitioned tables set `self.primary_key = :id`, so `find(id)` and associations work as now (Rails would otherwise infer the composite key from the schema).
- **`db/schema.rb` stays.** Rails 8.1 dumps a partitioned parent correctly (`options: "PARTITION BY RANGE (stored_at)"`, composite `primary_key:`), but dumps each partition as an `INHERITS` table, and fx 0.11 dumps every partition's cloned trigger (both verified). So partition names are added to `ActiveRecord::SchemaDumper.ignore_tables`, fx's trigger dump skips cloned triggers (`pg_trigger.tgparentid <> 0`), and `db:schema:load` and `db:prepare` are followed by `partitions:ensure`, which creates the partitions. Rejected: switching to `structure.sql`, whose `pg_dump` output differs between the local and CI PostgreSQL versions and would churn every parallel PR.

### The audit log's guards

What was verified on PostgreSQL 16 with today's guard function:

| Operation | Today (one table) | Partitioned |
|---|---|---|
| `UPDATE` or `DELETE`, through the parent or naming a partition | refused by `audit_entries_no_update_or_delete` | still refused: a row trigger on the parent is cloned to every partition, including ones created later |
| `UPDATE` that would move a row to another partition | refused | refused (fires as an update) |
| `TRUNCATE audit_entries` | refused by `audit_entries_no_truncate` | still refused |
| `TRUNCATE` naming one partition | n/a | **not refused**: a statement trigger is not cloned. The manager adds a `BEFORE TRUNCATE` trigger to each audit partition it creates (`audit_entries_partition_no_truncate`), and a spec checks every audit partition has one |
| `ALTER TABLE ... DETACH PARTITION`, `DROP TABLE` of a partition | n/a | **no trigger fires**, and a detached partition has lost its cloned triggers: the review detached an audit partition, updated a row (accepted), and attached it again, a forged entry with nothing logged |

The application runs DDL on these tables at run time, so a bug in the manager's choice of table is exactly the failure the guards exist to stop. The manager is create-only for audit, with a spec, but that is not enough on its own. So:

- **An event trigger, installed by the provisioning superuser**, refuses any `ALTER TABLE` on `audit_entries` or one of its partitions (`ddl_command_end`, `WHEN TAG IN ('ALTER TABLE')`, `object_identity LIKE 'public.audit_entries%'`) and any drop of one (`sql_drop`). Verified by the review on PostgreSQL 16: it refuses `DETACH`, `DROP`, and `DISABLE TRIGGER` from the non-superuser owner, while `CREATE TABLE ... PARTITION OF` (and the truncate trigger on a new partition) still work, and the owner cannot drop or disable the event trigger. That is stronger than today, where the owner role can disable the guard.
- The app never runs as a superuser, so it cannot install this itself. The SQL is a file in `ops/` that the PostgreSQL provisioning runs once as the superuser, **after** the audit conversion migration (the conversion's swap is an `ALTER TABLE`). For the homelab that is one step in the separate task that provisions the PostgreSQL container. The health endpoint warns when the event trigger is missing.
- **A later migration that alters `audit_entries`** (a new column) needs the superuser to disable the event trigger for it. That is deliberate.
- **The restore drill.** `pg_dump` includes event triggers, and `ops/backup/restore.sh` (`pg_restore --exit-on-error` as a non-superuser) fails on it with `permission denied to create event trigger` (verified by the review). `restore.sh` will restore from a `pg_restore -l` list without the event trigger, and the drill's instructions add "the superuser reinstalls the audit event trigger" after a real restore; the drill checks the health line.

## Migration from the current schema, online, at a million hosts

No rows are copied. The existing table becomes the "legacy" partition of a new parent, holding everything before a cutover time. Measured on the seed's `inventory_report_receipts` (1.2 million rows):

0. **Drop the old table's foreign keys**, one short statement each with `lock_timeout`. Each takes `ACCESS EXCLUSIVE` on the referenced table (`hosts`) for a moment, once; this is the only step that locks `hosts`, and it is the reason the new tables have no such keys.
1. **New parent, its partitions from the cutover on, and a default.** No lock on the old table. 0.5 s in all.
2. **Prepare the old table, without blocking writes.** `CREATE UNIQUE INDEX CONCURRENTLY` on `(id, <key>)` and `CREATE INDEX CONCURRENTLY` for each of the parent's indexes (1.2 s and 2.3 s here; about 35 minutes for 728 million receipt rows at a million hosts, still without blocking); `ADD CONSTRAINT ... CHECK (<key> < cutover) NOT VALID`, then `VALIDATE CONSTRAINT` (0.19 s; takes only a `SHARE UPDATE EXCLUSIVE` lock). For a `stored_at` table first: `ADD COLUMN stored_at timestamp NOT NULL DEFAULT '2000-01-01'`, a catalog-only change in PostgreSQL 11 and later (5 ms on `config_snapshots`), then `SET DEFAULT now()` after the swap.
3. **The swap, one short transaction with `lock_timeout`:** replace the old primary key with the new unique index, drop the old unique index, rename the old table to `<table>_legacy` and the new parent to `<table>`, `ATTACH PARTITION <table>_legacy FOR VALUES FROM (MINVALUE) TO (cutover)` (the validated `CHECK` lets PostgreSQL skip the scan), and move the sequence. **About 25 ms of statements and an 82 ms commit** here (the review measured 7 ms and 244 ms on another run), the same at any size: nothing is read or written row by row. With the foreign keys gone, the attach no longer locks `hosts` (with them, it took `ACCESS EXCLUSIVE` on `hosts` for the commit, as the review found).
4. **The legacy partition ages out.** Until its upper bound (the cutover) is older than the window, `Retention` keeps row-deleting inside it, as today. Then it is retired like any partition (its kept rows moved forward 1,000 at a time): 7 days after the cutover for receipts, one retention window for the rest. Detaching and dropping the 1.2 million-row legacy partition took 1.2 ms plus a 6.5 ms commit, then 198 ms for the `DROP`.

The code that no longer needs the old unique index (duplicate detection under the host lock, `self.primary_key = :id`) deploys first; the migration follows. Each table is converted on its own, so a failed swap (the lock timeout) is simply retried. NFR-5 means the homelab could instead be rebuilt, but the conversion is the same code at any size, so there is one path.

## How retention, matching, and the dashboard change

- **Retention.** `Retention.register` gains `partitioned: true`. For those tables a run retires every partition whose upper bound is at or before the cutoff (copy forward first where the newest row is kept), and row-deletes only inside a legacy partition. A dry run counts the rows in the partitions it would retire. On the seed, one pass over `inventory_snapshots` in weekly partitions retired 16 partitions (53,336 rows) and kept 6,667 rows (the third of hosts whose snapshots are all old) in **0.6 to 1.5 s** (two runs, with the kept rows copied; moving them by `UPDATE` is the same work), against the row-by-row cost of 0.024 ms for each of those 53,336 rows plus the anti-join per batch.
- **What is kept changes slightly.** A partition is retired only once all of it is past the window, so rows are kept for the window plus up to one partition width: up to 7 more days of snapshots (73,338 rows kept on the seed against 60,004 with row deletes) and up to 1 more day of receipts. NFR-2 asks for "at least 90 days", so this stays within it. The settings page's wording says "kept for at least N days".
- **Matching and CIS evaluation** read current state (`host_packages`, `host_configs`, `cis_results`), which is not partitioned. Unchanged.
- **The dashboard.** History pages read one host's rows by `(host_id, received_at)`, which no partition can be pruned for, so the query probes every partition's index. On the seed, a host's newest inventory snapshot over 31 weekly partitions took 0.44 ms against 0.43 ms unpartitioned; planning is about 2 ms more the first time in a connection (prepared statements reuse it). So the number of partitions is kept small (the widths above). The audit page's keyset pages read the newest month first and stop at the limit; its host filter probes one index a month (12 a year).
- **Backups.** `pg_dump` dumps partitioned tables without change, and the restore check counts the parents. Two interactions are handled above: maintenance does no DDL while the dump runs (decision 6), and the restore drill skips the audit event trigger and has it reinstalled (the audit guards).

## The homelab

The same code with no setting and no new service. About 130 small tables appear in `psql \d` (3 receipt tables of about 8 daily partitions plus 3 ahead, 5 tables of about 14 weekly partitions plus 3 ahead, the audit log's months, and a default for each). The hourly job takes well under a second at 50 hosts. Nothing is installed in PostgreSQL; the audit event trigger is one SQL file the PostgreSQL provisioning runs once as the superuser (the app works without it, and the health page then warns). Retention is still `retention.days`.

## Risks

- **A missing partition** sends rows to the default partition: no write fails, but the health page warns, and the manager must move the rows before it can create that range (creating a partition whose range has rows in the default fails; verified). For `audit_entries` a missing partition fails the write (decision 5).
- **Lock queues.** Creating and detaching wait for running queries on the parent, and queued queries then wait behind them. `lock_timeout = 150ms`, a few tries an hour, and no DDL during the backup bound that wait; the 3-day health warning catches a table that never gets its turn.
- **No foreign keys** on the history tables: a bug could write a row for a host that does not exist. Hosts are never deleted and writers hold the host's lock, and `partitions:check` reports orphans.
- **Planning time grows with partitions:** the reason for the widths and for keeping only a few partitions ahead.
- **Ids are unique by sequence, not by constraint.** A bug that inserts an explicit id could duplicate one; no code path does (moving a row forward is an `UPDATE`).
- **Two small patches to tooling** (the dumper's ignore list and fx's trigger dump) must be kept working across Rails and fx upgrades; a spec loads the schema into an empty database and compares.
- **Without the event trigger** (not yet provisioned, or after a restore before it is reinstalled), the owner role can detach, change, and reattach an audit partition, as it can disable the guard today. The health page says so.

## How it will be tested and measured

- Specs: the manager creates the right partitions ahead and is idempotent; retiring keeps each host's newest row (for every host with rows before, at least one row after, and it is the newest) and keeps its id, in batches; nothing is dropped inside the window; audit partitions are only created, each has its truncate trigger, and audit has no default; `UPDATE`, `DELETE`, and `TRUNCATE` on the audit parent and on a partition are refused; with the event trigger installed (CI's PostgreSQL service is a superuser), `DETACH`, `DROP`, and `DISABLE TRIGGER` on audit are refused for a non-superuser owner role; a lock timeout leaves everything as it was and is retried; no DDL while a `pg_dump` session runs; the default partition repair; receipt duplicates are still refused under the host lock; `partitions:check` finds an orphan.
- The restore drill runs with the event trigger present.
- A migration spec converts a populated table and checks every row, id, and index; the schema loads into an empty database and matches.
- `bin/benchmark jobs` reports retention as partitions retired, rows moved forward, and time; `explain` covers the history queries. Before and after, on the benchmark seed: today's 0.024 ms a row against a time per partition that does not grow with its rows.
- 100% line coverage, as now.

## Building it

One issue each, in this order; each PR is small enough to review alone.

1. **Partition manager and receipts** (needs #187): the manager, the hourly `PartitionMaintenanceJob` with its lock timeouts and backup check, `partitions:ensure` and `partitions:check`, the schema dump changes, default partitions and their health lines, and the three receipt tables converted (their foreign keys dropped), with duplicate detection under the host lock.
2. **Snapshots and status events:** `stored_at`, retirement that moves kept rows forward in batches, `self.primary_key`, the foreign keys dropped (out to `hosts` and the CIS tables, in from `cis_results` and `cis_result_changes`) and their readers, the four tables converted; `cis_result_changes` converted.
3. **Audit log:** monthly partitions with no default, the per-partition truncate trigger, the event trigger SQL in `ops/` with the provisioning step, `restore.sh` and the drill's instructions, and the health lines. Needs the owner's provisioning change.
4. **Docs and benchmark:** `docs/operations/health-and-jobs.md` (partitions, the default partition, repair), P1-S10's text in `p1-operability.md`, and `bin/benchmark` measuring retention by partition.

## Consequences

- Daily retention cost no longer grows with the rows written: at a million hosts, dropping a day of receipts is one catalog operation instead of 42 minutes of deletes and their vacuum.
- History is kept up to one partition width longer than the window.
- A few table properties change shape: composite primary keys, receipts deduplicated under the host lock, no foreign keys on the history tables, and soft references from CIS results to config snapshots.
- The audit log gains a guard the owner role cannot remove, at the cost of a superuser step in provisioning and in a restore.
- Audit and task growth is not bounded by this ADR. The audit log becomes archivable by month, but archiving needs the owner's decision on FR-S.3.
