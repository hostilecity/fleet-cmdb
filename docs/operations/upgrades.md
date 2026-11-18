# Upgrades that need a step of their own

Almost every upgrade is a merge to `main`: the deploy builds the image, starts the container, and the container migrates the database as it starts (`db:prepare`, [install-server.md](install-server.md#7-upgrade-change-a-setting-roll-back)). This page lists the upgrades that can need more, what they cost, and what to do.

**How such an upgrade shows itself.** A migration that would take too long at container start refuses before it changes anything, with a log line that starts `fleet-cmdb upgrade step needed:`. The container then stays up without serving: it does not restart into the migration again. `docker ps` still shows it `Up` (the image has no health check), while `/up` refuses connections, so the deploy's wait for `/up` fails and prints the container's log. **The dashboard and the agent API are down until the step is done**, for its whole length (hours on a very large database). Agents keep running and retry. They do not queue or replay what they missed (requirements, FR-1.2): when the server is back they send their current state. So changes in between are recorded as the state they led to, not one by one, and the hosts' status history has a gap for the outage.

## Package sets (#196, ADR 0028)

The upgrade moves every host's package list and every package snapshot into content-addressed package sets, copies each finding's details, and drops `host_packages` and the snapshots' JSON lists.

- **Small databases (a homelab):** nothing to do. The migration runs at container start when its estimate (30 ms for each distinct package list, that is a host's current one and each kept snapshot, plus 0.12 ms per finding) is at most 90 s. Measured on 2 shared CPUs: 2,002 distinct lists and 225,450 findings (an estimate of 87 s) took 62 s, and 66 s with the boot and the other migrations, under a load average of 8, against the deploy's 300 s wait. 50 hosts with 90 days of snapshots take a few seconds.
- **Large databases:** above that estimate, the migration refuses at container start (see above). Measured on 2 shared CPUs, the backfill is linear in the number of distinct lists: about 25 to 50 minutes for 100,000, and 4 to 9 hours for 1,000,000 (`docs/decisions/0028-content-addressed-package-sets.md`, "As built", item 1).

When it refuses, on the server VM, as the deploy user:

1. **Keep the deploy and the backup away while it runs.** A deploy would replace the waiting container and kill the backfill, and a backup's `pg_dump` would block the restart's migration.
   - Disable the Deploy workflow (GitHub: Actions, Deploy, "Disable workflow"; or `gh workflow disable Deploy`), and merge nothing to `main` until you are done.
   - Stop the backup timer: `systemctl --user stop fleet-cmdb-backup.timer`.
   - Run the step under the backup lock, as below. A backup or deploy that starts anyway then waits for it (a deploy for up to 20 minutes, then it fails without replacing the app; a backup for up to an hour).
2. **Run the backfill in the waiting container, then restart it, under the lock.** The waiting container has the app's settings; a new one would not (the deploy deletes its settings file).

   ```sh
   lock=~/.local/state/fleet-cmdb/backup.lock; log=~/packages-backfill.log
   nohup flock "$lock" sh -c "echo 'package backfill since $(date -u +%FT%TZ)' > $lock; \
     docker exec fleet-cmdb bin/rails packages:backfill && docker restart fleet-cmdb && sleep 60" > "$log" 2>&1 &
   tail -f "$log"    # progress every 1,000 lists; Ctrl-C stops only the tail
   ```

   When it prints `Done.`, the restart's migrations finish the upgrade in seconds. The `sleep 60` keeps the lock until they have.
3. **Check, and turn things back on.**

   ```sh
   docker exec fleet-cmdb bin/rails packages:check_snapshots   # "every reference is sound"
   systemctl --user start fleet-cmdb-backup.timer
   ```

   Enable the Deploy workflow again. If `FLEET_JOBS_CONTAINER` is `true`, the failed deploy never started the jobs container, so run the workflow once (Actions, Deploy, "Run workflow") to bring it back.

- `packages:backfill` is resumable: if it is stopped or interrupted, run step 2 again and it carries on with what is left. It only adds; it never deletes anything. A second one started while one runs refuses (`another package backfill is running`).
- Do not run `bin/rails db:migrate:redo` or roll the migrations back: rolling back `BackfillPackageSets` empties the package store, matched verdicts included.
- The old space stays: the findings keep their wider rows, and `package_snapshots` keeps the space of its JSON lists, until rows are rewritten (old snapshots also leave with retention). To get it back at once on a large database, rebuild the tables at a quiet time (`VACUUM FULL vulnerability_findings` and `VACUUM FULL package_snapshots`, which lock each table while they run).
- After the upgrade no package chunk is matched yet: findings keep the state they had and show their copied details, and each host's chunks are matched at its next package report or advisory import. `bin/rails vulnerabilities:match` matches everything at once.
