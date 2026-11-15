# ADR 0025: The dashboard reads per-host summaries kept by the database, in keyset pages

- Status: Proposed (#193; owner approval needed)
- Decision issue: #193
- Requirements: `FR-1.5`, `FR-2.5`, `NFR-3`; replaces one known limit of [ADR 0019](0019-scale-direction.md)

## Context

The fleet list listed every host on one page, and both it and the compliance page counted every host's CIS results and open findings on every view: 31 s and 29 s of database time at 100,000 hosts, about 3 s at 10,000 (performance assessment P-05, `bin/benchmark explain`). Every live refresh runs the page again for every open browser. ADR 0019 accepted "fleet counts recomputed per live broadcast" as a prototype limit and asked for an ADR when it is replaced.

## Decision

- **One summary row per host**, `host_compliance_summaries`: CIS pass, fail, and not readable counts, open failures by severity, open and reopened findings by severity, whether matching evaluated the host, and copies of the host fields the fleet list sorts and filters by (name, hostname, tags, agent version, enrollment state, liveness, operating system). Derived values (pass rate, the sort keys) are generated columns.
- **Kept by the database, in the writing transaction.** Triggers on `hosts`, `host_inventories`, `cis_results`, `cis_rules`, `vulnerability_findings`, `advisories`, and `host_vulnerability_evaluations` recount or copy the affected hosts in the transaction that changed their rows, whichever code wrote them (the application, a bulk SQL update, the benchmark seed). A recount locks the host's summary row first and counts in a later statement, so two transactions changing one host at once both end up counted. Unchanged rows are not rewritten.
- **Fleet-wide counts are one sum** over the active hosts' summaries, not a separate counter row: no hot row for every evaluation to wait on.
- **Keyset pages of 100** on the fleet list and the compliance page, after or before a cursor host, in each sort's current order (ties by name, NULLs last in either direction). Every sort has an index on the summaries with the name tie-break, except "last seen": `last_seen_at` changes on every heartbeat, and indexing it would cost every heartbeat its heap-only update.
- `bin/rails compliance_summaries:check` and `compliance_summaries:rebuild` compare and recount every host from its rows, for an operator who restored data with triggers off or suspects drift.

Rejected:
- Updating the summaries from application code (CisEvaluation, VulnerabilityMatcher): every other writer, present and future, would have to remember, and a missed one drifts silently.
- Incremental counters (add and subtract per change): cheaper per write, but a missed or doubled change drifts for ever; a recount of one host's 100 rows costs well under a millisecond.
- A materialized view refreshed on a schedule: stale between refreshes, and a refresh reads every host.
- Indexes on `hosts` for each sort: `last_seen_at` and `liveness_status` change with heartbeats and liveness, and every extra index on that hot, wide row costs every non-heap-only update (#192).

## Consequences

- Both pages cost about the same at 100,000 hosts as at 50, whatever the page; the numbers are in #193's pull request and `docs/operations/benchmark.md`.
- Writes that change a host's compliance do a little more work: one locked recount per host changed, in the same transaction. A rule change at 100,000 hosts recounts each host whose result changed.
- The summaries are derived data: a database restored with triggers disabled must be rebuilt (`docs/operations/compliance-summaries.md`).
- "Last seen" stays a sort of the filtered fleet. At 100,000 hosts it is the one sort that grows with the fleet; moving `last_seen_at` off the `hosts` row (#192) would let it have an index.
- The fleet list and the compliance page show "N hosts shown of M" with Previous and Next, not page numbers.
