# Upgrades that need a step of their own

Almost every upgrade is a merge to `main`: the deploy builds the image, starts the container, and the container migrates the database as it starts (`db:prepare`, [install-server.md](install-server.md#7-upgrade-change-a-setting-roll-back)). This page lists the upgrades that can need more, what they cost, and what to do.

**How such an upgrade shows itself.** A migration that would take too long at container start refuses before it changes anything, with a log line that starts `fleet-cmdb upgrade step needed:`. The container then stays up without serving: it does not restart into the migration again. `docker ps` still shows it `Up` (the image has no health check), while `/up` refuses connections, so the deploy's wait for `/up` fails and prints the container's log. **The dashboard and the agent API are down until the step is done**, for its whole length (hours on a very large database). Agents keep running and retry. They do not queue or replay what they missed (requirements, FR-1.2): when the server is back they send their current state. So changes in between are recorded as the state they led to, not one by one, and the hosts' status history has a gap for the outage.

## Package sets (#196, ADR 0028)

The upgrade moves every host's package list and every package snapshot into content-addressed package sets, copies each finding's details, and drops `host_packages` and the snapshots' JSON lists.

- **Small databases (a homelab):** nothing to do. The migration runs at container start when its estimate is at most 90 s. The estimate (`PackageStoreBackfill#estimate`) adds:
  - 30 ms for each distinct package list (a host's current one and each kept snapshot), and 0.02 ms for each package in those lists;
  - 0.18 ms for each package of a chunk that is not stored yet: every package when that still fits in 90 s, otherwise the packages of the distinct new chunks, counted in SQL (for at most 30 s; past that, every package);
  - 0.1 ms for each snapshot or host row, and 0.12 ms for each finding.

  The rates are about three times those measured on a quiet machine with 2 CPUs, so a busy VM still finishes within the deploy's 300 s wait. The estimate counts in that order and stops once it is past 90 s, so on a large database it reads only part of it.

  | Case | Estimate | Measured, load 1 | Measured, load 9 to 11 |
  | --- | --- | --- | --- |
  | 50 hosts from one image, 30 service packages of their own, weekly upgrades for 13 weeks: 700 lists, 581,000 packages, 33,053 in new chunks | 39 s | 12 s | |
  | 50 hosts in 3 roles, 90 days: 121 lists, 97,402 packages, 700 rows, 20,000 findings | 26 s | 2.5 s | 9 s |
  | 1,500 lists of 20 packages | 51 s | 14 s | |
  | 300,000 findings on 30 hosts | 36 s | 5.4 s | |
  | The same findings, with ids spread up to 2,000,000,000 | 36 s | 5.0 s | |
  | 400,000 snapshot rows over 20 lists | 41 s | 8.7 s | 38 s |
  | 10 lists of 3,000 packages on 200,000 rows | 26 s | 2.4 s | |
  | 500 distinct lists of 3,000 packages | 315 s (refused) | 92 s | 302 s |

- **Large databases:** above that estimate, the migration refuses at container start (see above). Measured on 2 shared CPUs, the backfill is linear in the number of distinct lists: about 25 to 50 minutes for 100,000, and 4 to 9 hours for 1,000,000 (`docs/decisions/0028-content-addressed-package-sets.md`, "As built", item 1).

When it refuses, on the server VM, as the deploy user:

1. **Keep the deploy and the backup away while it runs.** A deploy would replace the waiting container and kill the backfill, and a backup's `pg_dump` would block the restart's migration.
   - Disable the Deploy workflow (GitHub: Actions, Deploy, "Disable workflow"; or `gh workflow disable Deploy`), and merge nothing to `main` until you are done.
   - Stop the backup timer: `systemctl --user stop fleet-cmdb-backup.timer`.
   - The step runs under the backup lock (below), so a backup or deploy that starts anyway waits for it: a deploy for up to 20 minutes, then it fails without replacing the app; a backup for up to an hour.
2. **Run the backfill in the waiting container, then restart it, under the lock,** with the script the deploy installs beside the backup's (`ops/backup/package-backfill.sh`). The waiting container has the app's settings; a new one would not (the deploy deletes its settings file).

   ```sh
   nohup ~/.local/share/fleet-cmdb/backup/package-backfill.sh > ~/packages-backfill.log 2>&1 &
   tail -f ~/packages-backfill.log    # progress every 1,000 lists; Ctrl-C stops only the tail
   ```

   It takes the backup lock as the backup does (`ops/backup/lock.sh`): it waits up to an hour for a running backup or drill, refuses at once while a restore runs or while an unfinished restore left its marker (checked again once it holds the lock), and writes its holder line (`package backfill since <time>, pid <pid>`). Then it runs `bin/rails packages:backfill` in the container, restarts it, and keeps the lock until the app answers `/up` on ports 3000 and 3443, so the restart's migrations finish before anything else takes it. It ends with `done: fleet-cmdb serves again`, or says why it stopped:
   - **Interrupted** (Ctrl-C in a foreground run, or `kill` of the script) during the backfill: it stops the backfill in the container (the batch in progress rolls back) and does not restart the app, which still waits. The lock is released. Run step 2 again to carry on. If the backfill had not stopped after a minute, it says so; a second one reports `another package backfill is running` until it does.
   - **The app exits and restarts by itself, stops, or refuses again** after the restart: it stops waiting at once, releases the lock, and prints the end of the app's log.
   - **No `/up` within 30 minutes** (`FLEET_BACKFILL_UP_WAIT`, in seconds): it releases the lock although the migrations may still run. Keep the backup timer stopped and the Deploy workflow disabled until the app serves (`docker logs fleet-cmdb`).
3. **Check, and turn things back on.**

   ```sh
   docker exec fleet-cmdb bin/rails packages:check_snapshots   # "every reference is sound"
   systemctl --user start fleet-cmdb-backup.timer
   ```

   Enable the Deploy workflow again. If `FLEET_JOBS_CONTAINER` is `true`, the failed deploy never started the jobs container, so run the workflow once (Actions, Deploy, "Run workflow") to bring it back.

- The backfill is resumable: if it is stopped or interrupted, run step 2 again and it carries on with what is left. It only adds; it never deletes anything. A second one started while one runs refuses (`another package backfill is running`).
- Do not run `bin/rails db:migrate:redo` or roll the migrations back: rolling back `BackfillPackageSets` empties the package store, matched verdicts included.
- The old space stays: the findings keep their wider rows, and `package_snapshots` keeps the space of its JSON lists, until rows are rewritten (old snapshots also leave with retention). To get it back at once on a large database, rebuild the tables at a quiet time (`VACUUM FULL vulnerability_findings` and `VACUUM FULL package_snapshots`, which lock each table while they run).
- After the upgrade no package chunk is matched yet: findings keep the state they had and show their copied details, and each host's chunks are matched at its next package report or advisory import. `bin/rails vulnerabilities:match` matches everything at once.
