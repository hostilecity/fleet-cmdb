# Compliance summaries

The fleet list and the compliance page read one row per host from `host_compliance_summaries` instead of counting every host's CIS results and findings on every view ([ADR 0026](../decisions/0026-dashboard-summaries-and-keyset-pages.md), #193). This page is for whoever runs the server and wants to know what keeps those rows right, and what to do if they are not.

## What a row holds

- The host's CIS-aligned pass, fail, and not readable counts, and its open failures by severity (the severity of the rule version each failure was counted under).
- Its open and reopened vulnerability findings by its advisories' severities, and whether its last matching run evaluated it.
- How many of those findings have a fix (`vuln_fixable`), on how many distinct packages and architectures (`vuln_fix_packages`), and which severities have one (`vuln_fix_severities`, a bit per severity: critical 1, high 2, medium 4, low 8, unknown 16). An open finding has a fix when its stored fixed version (`last_fixed_version`, which matching keeps current) is set (#256). A host that is not evaluated now counts none, though its kept findings stay open.
- Copies of the host fields the fleet list sorts and filters by: name, hostname, tags, agent version, enrollment state and liveness, and the operating system name from its inventory.

The pass rate and the sort keys are generated from these columns. Retired hosts keep their row; they are left out of every list and count.

## What keeps it right

Triggers in the database, whichever code makes the change: a CIS evaluation, a rule enabled, disabled, edited, or deleted, vulnerability matching (including an open finding gaining or losing a fix after an advisory import, which writes its stored fixed version with no change of state; a fix moving from one version to another changes no count), a host edited, revoked, re-enrolled, or retired, a liveness change (a row trigger on `host_liveness` that fires only when the status changes, so a steady heartbeat costs nothing here, #192), an inventory report with a new operating system. The triggers only note which hosts a transaction changed; when it commits, the summaries of those hosts are synced and recounted in one step, with their rows locked in host order. So a transaction never waits on a summary row in the middle of its work, and two transactions never deadlock on them; at most, one waits a moment for another's commit. A host whose shown values did not change is not rewritten, and a change of liveness alone moves only the status sort key.

An advisory import that changes a severity is different: it can move the counts of every host with an open finding for that advisory, and it is one long transaction. It only queues those hosts (`host_compliance_recounts`); `ComplianceSummaryRecountJob` recounts them in batches of 1,000 just after the import commits, then refreshes open fleet pages. Until it has run, those hosts' severity counts are a few seconds behind.

`TRUNCATE` is refused on the tables the counts come from (`cis_results`, `vulnerability_findings`, `host_vulnerability_evaluations`, `host_inventories`): it would skip the triggers. Delete the rows instead.

Nothing else writes the table, and there is no setting.

## Upgrading

The migration that creates the table (`20261110193000`) runs outside a transaction, so agents keep reporting while it runs: it creates the table and the triggers (each takes its table's lock for a moment), fills every existing host's row in batches of 1,000, each in its own short transaction, then builds the indexes concurrently and adds the foreign key without a long lock. At 100,000 hosts it took under a minute, and no heartbeat waited more than 0.3 s. If it stops partway, roll it back (`bin/rails db:migrate:down:primary VERSION=20261110193000`) and run it again.

The fix counts (#256) come in two migrations. `20261120256001` adds the three columns to the summaries (a metadata-only change; nothing is rewritten, and `vulnerability_findings` is not touched), replaces the counting functions, and makes the recount's progress row, in one short transaction. `20261120256002` then recounts every host, 100 at a time, each batch its own transaction with its progress, so a flush for those hosts waits at most one batch (0.8 s measured for 100 hosts with 3,560 open findings each). It runs at container start only when its estimate is at most 90 s; above that it refuses with the upgrade step, and `bin/rails compliance_summaries:recount_fixes` does it ([upgrades.md](upgrades.md#vulnerability-fix-counts-256)). Either way it runs before the server serves in the default deploy, so it is part of the deploy's downtime, not a window where the counts read 0. A recount that stops partway carries on from where it stopped. It costs about 4 to 8 ms a host with about 4,450 open findings ([benchmark.md](benchmark.md)), so the step is needed from roughly 10,000 such hosts (the estimate's rates are three times the measured ones), and takes about 2 hours of one connection at a million.

## Checking and rebuilding

```sh
bin/rails compliance_summaries:check     # compares every row with a fresh count; exits 1 and names the hosts if any differ
bin/rails compliance_summaries:rebuild   # recounts every host, creating any missing row
```

Both work in batches of 1,000 hosts, each in its own short transaction, so they can run with the server up; `check` writes nothing, locks each batch before reading it, and leaves out hosts still queued for a recount (it says how many). `rebuild` empties the queue for the hosts it recounts. In the container, prefix them as the other tasks are (`docker exec ... bin/rails ...`, see [install-server.md](install-server.md)).

Rebuild after anything that wrote the tables with triggers off: data loaded with `session_replication_role = replica` or `pg_restore --disable-triggers`, or rows copied in by hand. A backup restored with `ops/backup/restore.sh` ([backup-and-restore.md](backup-and-restore.md)) holds the summaries as they were when it was taken, which match the rest of the dump, so it needs no rebuild; `check` confirms it.
