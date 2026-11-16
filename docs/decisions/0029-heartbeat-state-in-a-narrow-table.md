# ADR 0029: Heartbeat state lives in a narrow table of its own

- Status: Proposed (#192; owner approval needed)
- Decision issue: #192 (finding P-14 of the performance assessment)
- Requirements: `FR-1.2`, `FR-1.4`, `NFR-3`
- Amends: [ADR 0026](0026-dashboard-summaries-and-keyset-pages.md), whose summaries now take the liveness status from `host_liveness`.

## Context

Every heartbeat updated the `hosts` row: about 600 bytes of heap, seven indexes (two GIN trigram, one GIN on tags), and a statement trigger with transition tables. PostgreSQL writes such an update heap-only (HOT: no index entries, the old version reclaimed on its page) only while the page has room and no indexed column changes. `hosts` had the default fill factor, and `liveness_status` was indexed, so every status change was a non-HOT update touching all seven indexes. On the scale benchmark, the first heartbeats after a `VACUUM` were 10 to 37% HOT, because the seeded pages were full. The liveness job scanned all of `hosts` three times a minute: 199 ms at 100,000 hosts.

## Decision

- **`host_liveness`, one row per host that has sent a heartbeat**: `last_seen_at`, `liveness_status`, and `agent_reported_at`, about 60 bytes, keyed by the host id. It has no index but its primary key, so a heartbeat never changes an indexed column. It keeps half of each page free (`fillfactor = 50`) for the next version of every row on it, and is vacuumed after 1% of its rows are dead (`autovacuum_vacuum_scale_factor = 0.01`). No row means "awaiting first contact". Its `evaluated` column records whether the host is active; a trigger on `hosts` keeps it in step with the enrollment state, so the liveness run never reads a revoked or retired host again (review of #220: without it, every retired host was found by every run, forever).
- **`hosts` is written only when what it holds changes.** The agent version, schema version, task capabilities, and `first_seen_at` stay on `hosts`. A heartbeat compares them with the locked row and writes only a difference. `task_capabilities_reported_at` is now the time of the heartbeat that first reported the capabilities as they are. The host's tasks page shows `last_seen_at` as the last report.
- **The heartbeat is one statement on `host_liveness`.** It returns the previous status, so the status event and the broadcast need no other read. The host row lock (`AgentHostLock`) is unchanged. Every writer of `host_liveness` holds that lock, so a reader holding it sees the latest committed row.
- **Liveness evaluation reads `host_liveness` once per run**, in one pass by host id, for the evaluated rows whose status is not the one their last heartbeat implies. It then locks only those hosts' rows (`FOR NO KEY UPDATE SKIP LOCKED`, active hosts only), reads them again under the locks, and moves them in batches of 1,000.
- **The summaries follow `host_liveness`** through row triggers that fire only when the status changes (`WHEN`), so a steady heartbeat queues nothing. The liveness-only path of the flush joins the marked ids instead of filtering by `= ANY`.
- **"Last seen" stays unindexed.** An index on `last_seen_at` would make every heartbeat a non-HOT update with two index entries, and a partial index would too: PostgreSQL checks every column an index names, predicate included. The sort stays a sort of the filtered fleet.

Rejected:
- Fill factor 70 and an autovacuum setting on `hosts` alone (the issue's first step). A heartbeat would still rewrite 600 bytes and fire the statement trigger, a status change would still touch seven indexes, and the job would still scan the wide table.
- A partial index on `last_seen_at` for online hosts, so each run reads only the hosts due to change. It breaks HOT for the same reason as a full index.
- A BRIN index on `last_seen_at`. It does not block HOT, but its ranges only widen, so it soon covers every page, and it cannot sort.
- Keeping `liveness_status` on `hosts`. The job needs both columns, so it would join the wide table again.
- A key-value store for heartbeats. It is a second required service, against the homelab's one-container default ([ADR 0025](0025-first-scale-step.md)). ADR 0019's path to ten million hosts still allows one later.

## Consequences

Measured with `bin/benchmark` at 100,001 hosts: 2 CPUs, PostgreSQL 16 with default settings, one production-mode Puma process with 3 threads, 6 client threads, a machine shared with other agents. Times are noisy; byte and row counts are not.

| | Before (`main`) | After |
|---|---|---|
| WAL a heartbeat, warm (3 runs of 30 s) | 486 to 512 bytes | 249 to 293 bytes |
| WAL a heartbeat, 2,000 hosts for 120 s (16,180 heartbeats) | 650 bytes | 337 bytes |
| Of which the `hosts` heap | 393 to 454 bytes (update and lock) | 54 to 107 bytes (the lock only) |
| HOT share of the row update | `hosts`: 10 to 37% on full pages, 95 to 99.7% warm, 97.3% over 120 s | `host_liveness`: 99.2 to 100%, 99.8% over 120 s; no `hosts` updates |
| Index growth over the 120 s run | none (44 MB on `hosts`); about 440 non-HOT updates added 7 index entries each | none (3 MB key index) |
| Table size | `hosts` 61 MB heap, 44 MB indexes | `host_liveness` 12 MB heap just after the copy, about 24 MB once settled (see below); 3 MB index |
| Heartbeat in process, SQL p50 / p99 | 3.4 / 6.7 ms | 2.3 / 5.5 ms |
| Heartbeat over HTTP, p50 | 43 to 45 ms, 134 to 137 req/s | 39 to 41 ms, 141 to 152 req/s |
| Liveness run, nothing changes | 199 ms (158 to 221) | 34 ms (23 to 35) |
| Liveness run, every host goes offline | 16.1 s (15.2 to 21.4) | 13.0 s (12.3 to 17.7) |
| Fleet list sorted by last seen, two pages | 455 ms of database time | 521 ms (mostly cold reads; no change) |

- **The first rounds after the migration are less HOT, and the table doubles once.** The copy fills pages to the fill factor, which leaves room for about one more version per row. The first rounds of heartbeats were about 80% HOT in the review's run (7,978 of 10,000 on 2,000 hosts), and the table grew from 30 to 61 pages before it settled at 98 to 100% HOT. So expect about twice the post-copy size: about 24 MB at 100,000 hosts, about 230 MB at a million (117 MB after the copy). That early dip is not a regression.
- The heartbeat still locks the `hosts` row, which writes a small WAL record and dirties the page, but leaves no dead tuple. So `hosts` no longer bloats from heartbeats.
- What still grows with the fleet is the liveness run's pass over the narrow table: about 0.3 ms per thousand hosts, so about 0.3 s a minute at a million hosts. Timer-driven liveness stays the step after that (ADR 0019).
- In a mass transition, most of the time is the status update with its per-row summary trigger (2.8 s of 13 s), against 4.3 s for the `hosts` update before.
- The migration runs in one transaction that locks `hosts` first, and gives up if the lock is not granted within 3 s, since every `hosts` query queues behind it while it waits. A first version took a weaker lock first and deadlocked with a heartbeat. Every query on `hosts` waits while it holds the lock:
  - up: 0.3 s at 100,000 hosts (no heartbeat waited over 0.4 s); 2.3 s at a million (the copy 1.8 s, the foreign key 0.6 s; review of #220);
  - down: 48 s at a million hosts, because copying the rows back rewrites every wide `hosts` row under its seven indexes and its statement trigger. Roll back at a quiet time, or rebuild the database instead (NFR-5).
- `db/schema.rb` carries the table's storage options by hand, because the Rails schema dumper leaves them out. `spec/models/host_liveness_spec.rb` checks them in the loaded schema.
