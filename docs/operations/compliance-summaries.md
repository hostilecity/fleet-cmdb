# Compliance summaries

The fleet list and the compliance page read one row per host from `host_compliance_summaries` instead of counting every host's CIS results and findings on every view ([ADR 0025](../decisions/0025-dashboard-summaries-and-keyset-pages.md), #193). This page is for whoever runs the server and wants to know what keeps those rows right, and what to do if they are not.

## What a row holds

- The host's CIS-aligned pass, fail, and not readable counts, and its open failures by severity (the severity of the rule version each failure was counted under).
- Its open and reopened vulnerability findings by its advisories' severities, and whether its last matching run evaluated it.
- Copies of the host fields the fleet list sorts and filters by: name, hostname, tags, agent version, enrollment state and liveness, and the operating system name from its inventory.

The pass rate and the sort keys are generated from these columns. Retired hosts keep their row; they are left out of every list and count.

## What keeps it right

Triggers in the database, in the same transaction as the change, whichever code makes it: a CIS evaluation, a rule enabled, disabled, edited, or deleted, vulnerability matching, an advisory import that changes a severity, a host edited, revoked, re-enrolled, or retired, an inventory report with a new operating system. Nothing else writes the table, and there is no setting. A host whose shown values did not change is not rewritten.

## Upgrading

The migration that creates the table (`20261110193000`) fills every existing host's row before the triggers are switched on. It reads every host's results and findings once: seconds on a homelab, about a minute at 100,000 hosts. Nothing else is needed.

## Checking and rebuilding

```sh
bin/rails compliance_summaries:check     # compares every row with a fresh count; exits 1 and names the hosts if any differ
bin/rails compliance_summaries:rebuild   # recounts every host, creating any missing row
```

Both work in batches of 1,000 hosts, each in its own short transaction, so they can run with the server up; `check` writes nothing. In the container, prefix them as the other tasks are (`docker exec ... bin/rails ...`, see [install-server.md](install-server.md)).

Rebuild after anything that wrote the tables with triggers off: data loaded with `session_replication_role = replica` or `pg_restore --disable-triggers`, or rows copied in by hand. A backup restored with `ops/backup/restore.sh` ([backup-and-restore.md](backup-and-restore.md)) holds the summaries as they were when it was taken, which match the rest of the dump, so it needs no rebuild; `check` confirms it.
