# Upgrades that need a step of their own

Almost every upgrade is a merge to `main`: the deploy builds the image, starts the container, and the container migrates the database as it starts (`db:prepare`, [install-server.md](install-server.md#7-upgrade-change-a-setting-roll-back)). This page lists the upgrades that can need more, what they cost, and what to do.

**How such an upgrade shows itself.** A migration that would take too long at container start refuses before it changes anything, with a log line that starts `fleet-cmdb upgrade step needed:`. The container then stays up without serving: it does not restart into the migration again. `docker ps` still shows it `Up` (the image has no health check), while `/up` refuses connections, so the deploy's wait for `/up` fails and prints the container's log. **The dashboard and the agent API are down until the step is done**, for its whole length (hours on a very large database). Agents keep running and retry. They do not queue or replay what they missed (requirements, FR-1.2): when the server is back they send their current state. So changes in between are recorded as the state they led to, not one by one, and the hosts' status history has a gap for the outage.

## Triage buckets for every open finding (#259)

Nothing to do: the upgrade queues its own work.

- **What runs.** The migration `TriageEveryFinding` queues one background re-triage of every host (an `EvaluationRun` of kind `triage`, reason "all"): every chunk verdict's base bucket is computed, then every host's findings get their bucket, rule, and KEV flag. It runs on the `evaluation` queue after the container starts, and its progress line on **Data sources** reads "Re-triaging every host's findings". If it stops, **Re-triage again** there, or `bin/rails vulnerabilities:triage`, starts it again.
- **What operators see meanwhile.** The open counts do not change. Until the run reaches a host, its bucket counts read 0 and do not yet add up to its open count. Nothing shows buckets yet: the host tab (VT-HOST-TAB, #260) and the fleet columns (VT-SCORES, #262) are later slices.
- **Cost.** About what a full re-match (`bin/rails vulnerabilities:match`) costs: each host's transitions read its verdicts and write each active finding once. The measurements are in the VT-BUCKETS PR and [vt-buckets.md](../backlog/specs/vt-buckets.md#as-built-259).
- **Large databases.** `ValidateTriageChecks` validates the two new checks at container start only on tables of at most 2 GB of heap, seconds of scanning with a warm cache and up to about a minute with a cold one after a restore (a scan that lets writes go on, though it holds off autovacuum on that table while it runs). Above that it leaves them `NOT VALID` (new rows are still checked) and logs it; run `docker exec fleet-cmdb bin/rails vulnerabilities:validate_triage_checks` while the server runs.
- **Rolling back.** The older code resolves findings without clearing their bucket, which the new check on `vulnerability_findings` refuses, so every package report that resolves a finding would fail. Drop the two checks first, then deploy the older image. The columns, counts, and functions can stay; the older code ignores them:

  ```sql
  ALTER TABLE vulnerability_findings DROP CONSTRAINT vulnerability_findings_bucket_valid;
  ALTER TABLE chunk_matches DROP CONSTRAINT chunk_matches_base_valid;
  ```

  (`docker exec -i fleet-cmdb bin/rails dbconsole` runs them.) After rolling forward again, run `bin/rails vulnerabilities:validate_triage_checks`, which clears the buckets the older code left on resolved findings, adds both checks back, and validates them, then `bin/rails vulnerabilities:triage`: findings the older code opened meanwhile have no bucket until it, or their host's next report, gives them one.

## Backports are matched against the release they are built from (#274)

Nothing to do: the next full advisory import does the work.

- **What changes.** Packages from trixie-backports (versions with `~bpo13+`) are also matched against `Debian:14` (forky) advisories, and trixie's data and Debian's triage for trixie no longer resolve, clear, or show beside their findings ([health-and-jobs.md](health-and-jobs.md#advisory-data)). Hosts with no backport see no change.
- **What runs at the upgrade.** `IndexBackportPackageEntries` builds a small partial index on the backports in `package_chunk_entries`, concurrently. `AddBackportVerdicts` (`20261122274003`; it adds a column only if it is missing) adds two columns to `chunk_matches`, with constant defaults, so nothing is rewritten. Nothing is re-matched yet: until a full import keeps `Debian:14`, backports are matched as before.
- **The first full import after the upgrade** (the scheduled refresh when OSV next changes its archive, most days; without the feed, `bin/rails advisories:import FILE=all.zip FULL=1`) stores `Debian:14`. It writes every stored advisory that names forky again: a record as modified as the stored one is written again when it names an ecosystem the stored one lacks. That import's line on **Data sources** therefore shows almost every DEBIAN-CVE record as "updated", and rewrites their `Debian:13` rows too, about one `advisory_packages` table's worth of dead rows for autovacuum. Only the `Debian:14` packages count as changed, and every stored backport's sources with them, so it re-matches only the hosts holding a backport. Findings trixie's fix had resolved on a backport whose source forky has no data for are reopened then. Malformed records or `Debian:14` entries in that import do not hold it back: they are skipped and counted, and **Data sources** shows the state. The next import is back to "unchanged".
- **What operators will see on a host with a backports kernel.** New findings for CVEs fixed in trixie's 6.12 series but not in the backport's, with forky's fix shown but not counted as Fix available. Fewer findings Ignorable or Low risk through Debian's triage for trixie. Some findings kept open that trixie's data had resolved. Each is expected.
- **Storage.** The `Debian:14` packages about double `advisory_packages` (one row per advisory, ecosystem, and source), and advisories that name only forky add `advisories` rows.
- **Rolling back.** The older code skips `Debian:14` and resolves the backports' findings on trixie's data again at their next match. After rolling forward, run `bin/rails vulnerabilities:rematch_backports`: it re-matches every backport's source, and only the hosts holding a backport.

## Backports-sloppy builds and the backports releases' freshness (#304)

Nothing to do, now or at forky's release.

- **What runs at the upgrade.** No migration and no re-match. Data sources gains two rows, `Debian:14` and `Debian:15`.
- **At forky's release.** OSV starts publishing `Debian:15`. The first full import that has it stores it (another release's worth of `advisory_packages` rows, about as many as `Debian:14`'s) and counts every stored backport's sources as changed under `Debian:15`, so it re-matches only the hosts holding a backport, once, as #274's first import did. Findings that `Debian:14` or trixie showed fixed, on a backport whose source `Debian:15` has no data for, reopen as kept then.
- **Rolling back.** The older code ignores `Debian:15` rows and matches against `Debian:14` alone. After rolling forward, run `bin/rails vulnerabilities:rematch_backports`.

## Signed kernel images get their findings (#270)

Nothing to do: the upgrade queues its own work. It is listed here because what the dashboard shows changes a lot, and so does the cost of kernel advisory imports.

- **What changes.** The running kernel's signed image (`linux-image-6.12.48+deb13-amd64`, source `linux-signed-amd64`), the `linux-image-amd64` metapackage, and `shim-signed` are now matched as `linux` and `shim`, the names Debian's advisories use (`cmdb/config/signed_sources.yml`, [health-and-jobs.md](health-and-jobs.md#advisory-data)). Before, they never got a finding.
- **What runs.** The migration `RematchSignedSources` queues one background re-match of `linux` and `shim`: the chunks holding them are matched again and every host on a set holding them moves its findings. It runs on the `evaluation` queue after the container starts. Its progress line on **Data sources** reads "Re-matching the hosts a change to how packages are matched affects" ([health-and-jobs.md](health-and-jobs.md#fleet-wide-evaluation)). If it stops, **Re-match again** there starts it again, and so does `bin/rails vulnerabilities:rematch SOURCES=linux,shim`.
- **What operators will see: a large jump in kernel findings on every amd64 and arm64 Debian host. That is expected and correct.**
  - Each kernel advisory that affects the running kernel now opens a finding on the signed image and on the `linux-image-amd64` metapackage. Hosts with headers or `linux-libc-dev` already had it on those. Every old kernel image still installed also gets the advisories fixed after it.
  - On a minimal server (no headers, no `linux-libc-dev`), the kernel's findings appear for the first time: 451 to 2,952 open findings a host in the measurement below. On a host with headers they go up by about 60% (4,201 to 6,702). The open and fixable counts on the fleet list, the Compliance page, and each Vulnerabilities tab rise with them.
  - Severity, Debian's triage, and the fixes are those of the `linux` advisories. Since VT-BUCKETS (#259) the triage buckets sort them: images installed but not running and the metapackages are Ignorable; the running image's fix is "reboot" or "install the new kernel, then reboot" ("Triage buckets", below).
- **Upgrading `linux-libc-dev` no longer clears the kernel's findings.** They resolve on the image when the image is removed (`apt autoremove` after booting the new kernel), and on the metapackage when it moves to the fixed version.
- **The update task cannot clear the metapackage's findings.** A new `linux-image-amd64` depends on a new image package, and the update task (`apply_package_updates`) runs `apt-get upgrade` without installing new packages (DEC-16), so apt keeps the metapackage back and its findings stay "Fix available". `apt upgrade` or `apt full-upgrade` on the host installs the new image and moves the metapackage; then reboot into the new kernel. Since VT-BUCKETS (#259) the metapackage's findings are Ignorable (no runtime code) and the running image carries the kernel's work; the host tab shows it as a kernel work item from VT-HOST-TAB (#260).
- **Kernel advisory imports now reach the whole amd64 and arm64 fleet.** An import re-matches the hosts holding a package whose advisories changed. Before, a `linux` change reached only the hosts with headers or `linux-libc-dev`; now it reaches every host with a signed image. Debian changes some `linux` entry most days, so most 6-hourly imports become fleet-wide runs. They write only the findings that change. #273 tracks reducing this.
- **Cost.** Measured on a container with 2 CPUs, in test-mode Rails, on 1,000 Debian 13 hosts: the simulator's 800 packages plus the signed image, the metapackage, shim and grub on all of them, and headers and `linux-libc-dev` on 100. The data was 1,250 kernel advisories (half fixed in 6.12.88-1), one for shim, and the simulator's 150. Times are medians of 3.

  | What | Before | After |
  | --- | --- | --- |
  | Open findings, minimal host / host with headers | 451 / 4,201 | 2,952 / 6,702 |
  | Hosts a routine kernel import re-matches (one `linux` entry changed) | 100 | 1,000 |
  | That import's re-match | 6.9 s (69 ms a host) | 41.5 s (41.5 ms a host) |
  | The upgrade's one-off re-match (2,501 new findings a host) | | about 570 ms a host |

  So a homelab finishes the upgrade's re-match in seconds, and 10,000 hosts take about 95 minutes on one evaluation thread. Each kernel import afterwards re-matches every amd64 and arm64 host, at a cost that grows with each host's open findings: 41.5 ms a host on this fleet (90% minimal hosts, 3,327 findings on average), and 69 ms on hosts with headers before this change. At 10,000 hosts that is about 7 to 12 minutes of one thread; at 1,000,000 hosts, about 11.5 thread-hours on a fleet like this one and 14 to 24 thread-hours at about 4,000 findings a host or with headers. More `EVALUATION_THREADS` divide both.
- **Rolling back.** The findings stay until the chunks are matched again (`bin/rails vulnerabilities:match`). The old code then reads the images' source as `linux-signed-amd64`, which no advisory names, so it resolves their findings as **not affected**. That resolution is an artefact of the rollback, not evidence that the kernel is fixed. **After rolling forward again, run `bin/rails vulnerabilities:rematch SOURCES=linux,shim`**: the migration has already run and does not queue its re-match again, and the old code's match marked every chunk current, so otherwise those resolutions stay until the next import that changes `linux` (days) or `shim` (possibly months).

## Package sets (#196, ADR 0028)

The upgrade moves every host's package list and every package snapshot into content-addressed package sets, copies each finding's details, and drops `host_packages` and the snapshots' JSON lists.

- **Small databases (a homelab):** nothing to do. The migration runs at container start when its estimate is at most 90 s. The estimate (`PackageStoreBackfill#estimate`) adds:
  - 30 ms for each distinct package list (a host's current one and each kept snapshot), and 0.02 ms for each package in those lists;
  - 0.18 ms for each package of each distinct chunk of the lists to move (a chunk already stored counts too): every package when that still fits in 90 s, otherwise the packages of the distinct chunks, counted in SQL (for at most 30 s; past that, every package);
  - 0.1 ms for each snapshot or host row, and 0.12 ms for each finding.

  The rates are about three times those measured on a quiet machine with 2 CPUs, so a busy VM still finishes within the deploy's 300 s wait. The estimate counts in that order and stops once it is past 90 s, so on a large database it reads only part of it, and the refusal then says only "more than 90 s": `bin/rails packages:backfill` prints what is left, and the rates above give the time.

  | Case | Estimate | Measured, load 1 | Measured, load 9 to 11 |
  | --- | --- | --- | --- |
  | 50 hosts from one image, 30 service packages of their own, weekly upgrades for 13 weeks: 700 lists, 581,000 packages, 33,053 in distinct chunks | 39 s | 12 s | |
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
   - **Interrupted while it waits for `/up`:** it keeps waiting, and keeps the lock, so the migrations finish alone. A second interrupt stops it; the lock is then released although the migrations may still run (check `docker logs fleet-cmdb`, and keep the timer stopped and Deploy disabled until the app serves).
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

## Vulnerability fix counts (#256)

The upgrade adds per-host counts of open findings with a fix to the compliance summaries, then recounts every host (migrations `20261120256001` and `20261120256002`; [compliance-summaries.md](compliance-summaries.md)).

- **Small databases (a homelab):** nothing to do. The recount runs at container start when its estimate is at most 90 s. The estimate (`ComplianceFixRecount#estimate`) adds 0.5 ms for each host and 5 microseconds for each open or reopened finding, about three times the rates measured on 2 shared CPUs (0.17 ms a host and about 1.6 microseconds a finding, [benchmark.md](benchmark.md)). It counts only until it is past 90 s, so the refusal on a large database says "more than 90 s". So the step is needed from about 180,000 hosts with no findings, or about 16,000 hosts with 1,000 open findings each. 100,001 hosts, 1,201 of them with 4,450 open findings each, took 25 s.
- **Large databases:** above that, the migration refuses with `fleet-cmdb upgrade step needed` before it recounts anything (see the top of this page: the container stays up without serving). The recount is linear in hosts and findings: about 2 hours for a million hosts with 4,450 open findings each.

When it refuses, on the server VM, as the deploy user:

1. **Keep the deploy away while it runs:** disable the Deploy workflow (`gh workflow disable Deploy`) and merge nothing to `main`. A deploy would replace the waiting container and stop the recount; that loses nothing, since it is resumable, but the new container would refuse again. Backups can run meanwhile: the recount only updates summary rows.
2. **Recount in the waiting container, then restart it:**

   ```sh
   nohup docker exec fleet-cmdb bin/rails compliance_summaries:recount_fixes > ~/fix-recount.log 2>&1 &
   tail -f ~/fix-recount.log    # what is left, then progress every 10,000 hosts; Ctrl-C stops only the tail
   docker restart fleet-cmdb    # when the log ends with "Done": the migration finds nothing left and finishes
   ```

   The task recounts 100 hosts at a time, each batch committed with its progress (the last host id done, in `compliance_fix_recounts`). If it stops (interrupted, the container restarted, the connection lost), run it again: it carries on after the last batch committed. Running it after the recount is finished says "Nothing to recount".
3. **Check, and turn the deploy back on:** `docker exec fleet-cmdb bin/rails compliance_summaries:check` ("Every host's compliance summary matches its rows"), then enable the Deploy workflow again. If `FLEET_JOBS_CONTAINER` is `true`, run the workflow once to bring the jobs container back.

- Do not roll `20261120256002` back to recount again: `compliance_summaries:rebuild` recounts every host whenever needed, with the server up.

## Exposure scores (#262)

The upgrade adds each host's exposure tier, points, work items, and run times to the compliance summaries, and each finding's listener (migrations `20261123262001` and `20261123262002`; [compliance-summaries.md](compliance-summaries.md)). The second builds the fleet list's Exposure and Work indexes concurrently (dropping and rebuilding one a stopped build left invalid), validates the listener check, writes each finding's listener from the listener evidence in force (in SQL, before the recount, so no host is scored without its listener points), and recounts every host. Until a host is recounted, its tiles, fleet list cells, and the Compliance page's bucket line say "not scored" or "Not triaged yet", never 0.

- **Small databases:** nothing to do. The listener backfill and the recount run inline at container start when their estimates add up to at most 90 s: 50 ms for each evaluated host with listener evidence (hosts with the library scan enabled, about three times the 18 ms measured), and the recount's 0.5 ms a host and 20 microseconds an open finding (about 2.5 times measured). So the step is needed from about 1,800 hosts that run the library scan, or about 4.5 million open findings, or a mix of the two.
- **Large databases:** the migration refuses with `fleet-cmdb upgrade step needed` before it writes anything. Follow the steps of the fix counts above with `compliance_summaries:recount_scores` in place of `compliance_summaries:recount_fixes` (its progress row is in `compliance_score_recounts`). Run it in the waiting container only, as those steps say: the server and the jobs container are down then, so no package report's re-triage runs beside the backfill. The task writes the listeners only while the recount has not started, so running it again after the recount, or with the upgrade finished, writes nothing. A refused attempt repeats only the index and check steps, which then find nothing to do, and once the recount has started the backfill is no longer counted, so the restart after the step finishes the upgrade.
- **The listener check:** on a `vulnerability_findings` heap over 2 GB the migration leaves `vulnerability_findings_listener_valid` NOT VALID and says so. Validate it with the server up, when convenient: `docker exec fleet-cmdb bin/rails vulnerabilities:validate_triage_checks`.
- Rolling back: `bin/rails db:migrate:down:primary VERSION=20261123262002` then `VERSION=20261123262001` drop the indexes, the columns, and the triggers, and restore the earlier functions.
