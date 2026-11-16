# ADR 0026: The dashboard reads per-host summaries kept by the database, in keyset pages

- Status: Proposed (#193; owner approval needed)
- Decision issue: #193
- Requirements: `FR-1.5`, `FR-2.5`, `NFR-3`; replaces one known limit of [ADR 0019](0019-scale-direction.md)

## Context

The fleet list listed every host on one page, and both it and the compliance page counted every host's CIS results and open findings on every view: 31 s and 29 s of database time at 100,000 hosts, about 3 s at 10,000 (performance assessment P-05, `bin/benchmark explain`). Every live refresh runs the page again for every open browser. ADR 0019 accepted "fleet counts recomputed per live broadcast" as a prototype limit and asked for an ADR when it is replaced.

## Decision

- **One summary row per host**, `host_compliance_summaries`: CIS pass, fail, and not readable counts, open failures by severity, open and reopened findings by severity, whether matching evaluated the host, and copies of the host fields the fleet list sorts and filters by (name, hostname, tags, agent version, enrollment state, liveness, operating system). Derived values (pass rate, the sort keys) are generated columns.
- **Kept by the database, recounted at commit.** Triggers on `hosts`, `host_inventories`, `cis_results`, `cis_rules`, `vulnerability_findings`, and `host_vulnerability_evaluations` only note which hosts a transaction changed, whichever code wrote them (the application, a bulk SQL update, the benchmark seed). One deferred constraint trigger then syncs and recounts those hosts when the transaction commits. It locks their summary rows in a single statement, in host id order, and counts in a later statement. As a result:
  - a transaction never waits on a summary row in the middle of its work, and Liveness's `SKIP LOCKED` statements never touch them;
  - two transactions never deadlock on summaries;
  - two transactions changing one host at once are both counted;
  - at most, one commit waits for another's recount.

  A change of liveness alone moves only the status sort key. Unchanged rows are not rewritten. `TRUNCATE` is refused on the source tables, since it would skip the triggers.
- **An advisory's new severity is recounted after the import.** It can move every host with an open finding for that advisory, and an import is one long transaction. So the import only queues those hosts (`host_compliance_recounts`). `ComplianceSummaryRecountJob` recounts them in sorted batches of 1,000 after the import commits, and their severity counts are a few seconds behind meanwhile.
- **Fleet-wide counts are one sum** over the active hosts' summaries, not a separate counter row: no hot row for every evaluation to wait on.
- **Keyset pages of 100** on the fleet list and the compliance page, after or before a cursor host, in each sort's current order (ties by name, NULLs last in either direction). Every sort has an index on the summaries with the name tie-break, except "last seen": `last_seen_at` changes on every heartbeat, and indexing it would cost every heartbeat its heap-only update.
- `bin/rails compliance_summaries:check` and `compliance_summaries:rebuild` compare and recount every host from its rows, for an operator who restored data with triggers off or suspects drift.

Rejected:
- Updating the summaries from application code (CisEvaluation, VulnerabilityMatcher): every other writer, present and future, would have to remember, and a missed one drifts silently.
- Incremental counters (add and subtract per change): cheaper per write, but a missed or doubled change drifts for ever; a recount of one host's 100 rows costs well under a millisecond.
- Recounting in each writing statement (this PR's first version): it held summary row locks from that statement to commit, in statement order. An open advisory import then made heartbeats that changed liveness, and CIS evaluations of the same hosts, wait for the whole import, and it deadlocked against a liveness run (review of #206).
- A materialized view refreshed on a schedule: stale between refreshes, and a refresh reads every host.
- Indexes on `hosts` for each sort: `last_seen_at` and `liveness_status` change with heartbeats and liveness, and every extra index on that hot, wide row costs every non-heap-only update (#192).

## Consequences

- At 100,000 hosts (`bin/benchmark explain`, #188), a page view costs 110 ms of database time on the fleet list and 95 ms on the compliance page, against 29.3 s and 22.5 s, and a page's rows about 1 ms on any page of any sort but last seen (about 0.3 s). What still grows with the fleet is three scans of the narrow summaries table per view (the fleet-wide counts, the status counts, and the tag list, together about 110 ms at 100,000 hosts), and the filters that read other tables (search, distribution).
- Writes that change a host's compliance do a little more work. They note the host in the writing transaction, and the commit locks and recounts it. Measured at 100,000 hosts, on a shared and busy machine, against the same database with the triggers disabled:
  - CIS evaluation: 66 to 67 ms a host, against 61 to 71 ms;
  - steady heartbeats and matching: no change beyond noise;
  - the whole fleet going offline at once: 21.6 s against 19.8 s (best of 3), +10%. The first version took 45.0 s on the same run, +127%.
  - re-measured after #186, where liveness moves hosts in transactions of 1,000 and each commit recounts its own batch: 16.2 s against 14.9 s (best of 6, alternating), +9%. The medians overlap (18.7 to 39.3 s against 15.4 to 17.6 s on the shared machine).

  A commit that changes a host waits only while another commit recounts that host.
- **The migration runs outside a transaction**, so agents keep working. It creates the triggers (short locks), fills the rows in batches of 1,000, then builds the indexes concurrently and adds the foreign key `NOT VALID` before validating it. At 100,000 hosts it took 48 s, and a probe heartbeat every 20 ms never waited more than 36 ms. The first version, in one transaction, blocked a heartbeat for its whole run (266 s on the same machine). On `main` after #186 and #204 it took 53 s, and the longest heartbeat wait was 293 ms, with none over 1 s.
- The summaries are derived data: a database restored with triggers disabled must be rebuilt (`docs/operations/compliance-summaries.md`). `compliance_summaries:check` leaves out hosts still queued for a recount.
- "Last seen" stays a sort of the filtered fleet. At 100,000 hosts it is the one sort that grows with the fleet. #192 moved `last_seen_at` off the `hosts` row, but an index on it in its new table would still cost every heartbeat its heap-only update, so it still has none ([ADR 0029](0029-heartbeat-state-in-a-narrow-table.md)).
- The fleet list and the compliance page show "N hosts shown of M" with Previous and Next, not page numbers.
