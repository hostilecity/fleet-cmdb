# Upgrades that need a step of their own

Almost every upgrade is a merge to `main`: the deploy builds the image, starts the container, and the container migrates the database as it starts (`db:prepare`, [install-server.md](install-server.md#7-upgrade-change-a-setting-roll-back)). This page lists the upgrades that can need more, what they cost, and what to do.

**How such an upgrade shows itself.** A migration that would take too long at container start refuses before it changes anything, with a log line that starts `fleet-cmdb upgrade step needed:`. The container then stays up without serving (it does not restart into the migration again), so the deploy's wait for `/up` fails and prints the container's log. Nothing else is wrong: agents retry their reports until the server is back, and nothing is lost.

## Package sets (#196, ADR 0028)

The upgrade moves every host's package list and every package snapshot into content-addressed package sets, copies each finding's details, and drops `host_packages` and the snapshots' JSON lists.

- **Small databases (a homelab):** nothing to do. The migration runs at container start: 15 to 30 ms for each distinct package list (a host's current one and each kept snapshot), plus about 10 s for every 100,000 findings. 50 hosts with 90 days of snapshots take a few seconds.
- **Large databases:** above 5,000 distinct package lists or 1,000,000 findings to copy, the migration refuses at container start (see above), because it might not finish inside the deploy's 5-minute wait. Measured on 2 shared CPUs: linear in the number of distinct lists, about 25 to 50 minutes for 100,000 and 4 to 9 hours for 1,000,000 (`docs/decisions/0028-content-addressed-package-sets.md`, "As built", item 1).

When it refuses, on the server VM, as the deploy user:

```sh
# The container is up but not serving; run the backfill inside it, detached, with its log on the storage volume.
docker exec -d fleet-cmdb sh -c 'bin/rails packages:backfill > storage/packages-backfill.log 2>&1'
docker exec fleet-cmdb tail -f storage/packages-backfill.log    # progress every 1,000 lists; Ctrl-C stops only the tail
# When it prints "Done.", start the server again: its migrations finish the upgrade in seconds.
docker restart fleet-cmdb
docker exec fleet-cmdb bin/rails packages:check_snapshots   # "every reference is sound"
```

- `packages:backfill` is resumable: stopped or interrupted, run it again and it carries on with what is left. It only adds; it never deletes anything.
- Do not run `bin/rails db:migrate:redo` or roll the migrations back: rolling back `BackfillPackageSets` empties the package store, matched verdicts included.
- If `FLEET_JOBS_CONTAINER` is `true`, the deploy starts the jobs container only after `/up` answers, so it is not running meanwhile; after the restart, run the workflow again (or start the jobs container as the deploy does) to bring it back.
- The old space stays: the findings keep their wider rows, and `package_snapshots` the space of its JSON lists, until rows are rewritten (old snapshots also leave with retention). To get it back at once on a large database, rebuild the tables at a quiet time (`VACUUM FULL vulnerability_findings` and `VACUUM FULL package_snapshots`, which lock each table while they run).
- After the upgrade no package chunk is matched yet: findings keep the state they had and show their copied details, and each host's chunks are matched at its next package report or advisory import. `bin/rails vulnerabilities:match` matches everything at once.
