# Backup and restore (P1-O01, NFR-2)

A backup that has never been restored is not a backup. This page says what is backed up, what is not, how to schedule it, how to restore, and how to prove it works (the restore drill). The scripts are in [`ops/backup/`](../../ops/backup/). Hostnames below are placeholders (`vm-01.example.lan`, `backup-01.example.lan`).

## What is backed up

| Data | In the backup set? | Why |
|---|---|---|
| Primary database (`cmdb_production`): hosts, snapshots, status history, the audit log, operators, release rows, settings | Yes, `fleet-cmdb.dump` (`pg_dump`, custom format) | Everything the fleet knows. |
| Queue, cache, and cable databases (`cmdb_production_queue`, `_cache`, `_cable`) | Yes, `queue.dump`, `cache.dump`, `cable.dump` | Pending and scheduled jobs survive a restore. The cache and cable databases hold only short-lived data, but dumping them is cheap, and a restore then brings back all four databases the app expects. |
| Release files (`FLEET_RELEASES_DIR`, `storage/releases` in the volume `fleet-cmdb_storage`) | Yes, `releases.tar` | An uploaded release cannot be re-imported from GitHub, and the database rows are checked against these files. Imported releases could be re-imported, but one tar covers both. |
| Row counts | Yes, `counts` | Taken just before the dump; the drill checks the restore holds at least this many hosts, audit entries, releases, and hosts with an inventory snapshot. A count query that fails stops the backup. |

Each run writes one directory, `fleet-cmdb-<UTC time>/`, with the files above and `SHA256SUMS`. It appears whole or not at all.

**Back up separately, never in this set and never in git** (the dump contains the whole inventory and audit log, and none of these):

- the `production` environment's secrets in GitHub ([install-server.md](install-server.md#2-create-the-github-environment)). GitHub never shows a secret again, so keep your own copy of each:
  - `SECRET_KEY_BASE`;
  - `FLEET_ENCRYPTION_KEY`: the dump holds operators' second-factor keys only encrypted with it, and recovery codes only as HMACs keyed from it. A restore without it works, but every operator's second factor must be reset (`bin/rails second_factor:reset EMAIL=…`) and set up again;
  - `DATABASE_PASSWORD`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and the server certificate and key (`FLEET_TLS_CERT`, `FLEET_TLS_KEY`; a new Origin certificate can be issued instead);
- the environment's variables (hostnames, the release public keys `FLEET_RELEASE_KEY_CURRENT` and `FLEET_RELEASE_KEY_NEXT`, the backup settings): not secret, but write them down;
- the Cloudflare tunnel's configuration and the deploy key (`SSH_PRIVATE_KEY`; a new one can be made instead).

Keep these in a password manager or an encrypted store, not on the same machine as the server. Treat backup sets as sensitive too: they belong to uid 1000 with mode 0700 (files 0600); restrict the backup location to that and encrypt it at rest.

## How it runs in the deployment

The backup runs on the app's VM ([install-server.md](install-server.md)), set up by the Deploy workflow (`.github/workflows/cd.yml`) on every deploy, before the app is replaced:

- **Settings.** The workflow writes `~/.config/fleet-cmdb/backup.env` for the deploy user (mode 0600): the database network, the backup location, and the backup variables below. It holds **no secret**. When a backup runs, `ops/backup/docker.sh` reads the database host and password from the `fleet-cmdb` container's settings (`docker inspect`, which works while the container is stopped too) and hands the password to its containers through the environment (`docker run -e PGPASSWORD`). So the password is never stored for the backup, and never appears on a command line or in `ps`. The backup therefore needs the `fleet-cmdb` container to exist.
- **Timer.** `ops/backup/install.sh` copies `ops/backup/` to `~/.local/share/fleet-cmdb/backup/` and installs the deploy user's systemd timer `fleet-cmdb-backup.timer`: daily at 02:30 with up to 10 minutes' random delay, caught up at boot after a missed run. It is a user unit, so the workflow needs no root; the user's systemd instance must run without a login (once, as root: `loginctl enable-linger deploy`). If that is missing, the deploy stops there, before the app is replaced.
- **The backup.** `docker.sh backup` checks that `BACKUP_DIR` exists and is a mount point on the VM, then runs `ops/backup/backup.sh` in a throwaway `postgres:17` container on the database's Docker network (`FLEET_DB_NETWORK`), so the database needs no published port and the VM no PostgreSQL client. That container runs as the app's uid 1000 with no Linux capabilities, and mounts the app's volume `fleet-cmdb_storage` **read-only**, for the release files. Once the set is complete, a container of the app's own image, with no network, touches the status file in that volume (`/rails/storage/backup/last_success`), which `/health` reads.
- **No empty set displaces a good one.** Hosts and audit entries are never deleted. So a backup refuses a database that holds fewer of either than the newest set recorded: it writes nothing, prunes nothing, and leaves the status file alone, so `/health` turns unhealthy. That is what happens after a rebuilt server comes up on empty databases, until a set is restored. After restoring an older set on purpose, `docker.sh restore` takes the next backup itself, forced; otherwise force one with `docker.sh backup --force`.
- **The first backup.** A deploy starts a backup in the background only when the backup location holds **no set at all**, so a new install is healthy within minutes. It never does after a rebuild: the old sets are there.
- **One at a time.** Backup, restore drill, restore, and deploy share one lock (`~/.local/state/fleet-cmdb/backup.lock`). A backup or drill waits up to an hour for another holder. A deploy waits up to 30 minutes for a running backup before it builds anything: a running `pg_dump` holds a share lock on every table, so the new app's migrations would otherwise queue behind it, and every query on those tables behind the migrations. A restore refuses while anything else runs, and everything else refuses while a restore runs: the timer's backup, the drill, and the deploy (before it touches the app).
- **Client version.** `pg_dump` must be the server's major version or newer. `backup.sh` checks this first and names both versions if not; set `FLEET_BACKUP_PG_IMAGE` (for example `postgres:18`) to match a newer server. Each deploy pulls the image again, so its patch releases arrive; if the pull fails, the copy already on the VM is used and the deploy only warns. To run exactly the image you checked, pin it by digest, for example `postgres:17@sha256:<digest>`.

| Variable (production environment) | Default | |
|---|---|---|
| `FLEET_BACKUP_DIR` | `/var/backups/fleet-cmdb` | Where the sets are kept on the VM. Mount an off-machine location there (NFS, SMB, or similar) that uid 1000 can write |
| `FLEET_BACKUP_ALLOW_LOCAL` | `false` | `true` lets the backup write to a directory that is not a mount point. The sets then share the VM's disk with the database, and losing the VM loses both |
| `FLEET_BACKUP_RETENTION_DAYS` | `14` | Sets taken more than this many days ago (by the time in their name) are deleted after a successful backup. The newest 3, and the newest set that holds any host, are always kept |
| `FLEET_BACKUP_PG_IMAGE` | `postgres:17` | The PostgreSQL client image; its major version must be the server's or newer. May be pinned by digest |
| `FLEET_BACKUP_DRILL_HOST` | unset: the live server | Another PostgreSQL server on the same Docker network for the restore drill's scratch databases (see the drill below) |

The one-time steps on the VM and in PostgreSQL are in [install-server.md](install-server.md#1-check-the-prerequisites).

Useful commands on the VM, as the deploy user:

```sh
B=~/.local/share/fleet-cmdb/backup/docker.sh
systemctl --user list-timers fleet-cmdb-backup.timer      # the next run
$B backup                                                 # a backup now
journalctl --user -u fleet-cmdb-backup.service -n 30      # the timer's last runs
$B list                                                   # the sets, their sizes, and their counts
```

`journalctl --user` shows the deploy user's own journal only when the journal is persistent (the directory `/var/log/journal` exists). Otherwise read it as root: `journalctl _SYSTEMD_USER_UNIT=fleet-cmdb-backup.service -n 30`.

Without the deployment (the app run by hand, with PostgreSQL client tools on the machine), run `ops/backup/backup.sh` directly with the variables listed at its top.

**At larger scale.** A nightly logical dump suits a homelab-sized database (seconds, a few MB). It does not suit a very large one: the dump holds one snapshot and a share lock on every table for its whole run (so deploys wait for it, and partition maintenance would too), both the dump and the restore are single-threaded, up to a day of data can be lost, and every set is a full copy. Physical backups with WAL archiving and point-in-time recovery (for example pgBackRest or WAL-G, ideally from a standby) are the step for that, proposed as a separate backlog item and not built here.

## Know when backups stop

After a complete backup the script touches `FLEET_BACKUP_STATUS_FILE`. `GET /health` (agent hostname or localhost) reports the backup check as failing, and the whole endpoint as 503, when that file is missing or older than `FLEET_BACKUP_MAX_AGE_HOURS` (26). A fresh install therefore reports unhealthy until its first backup, which the first deploy starts in the background. So does a rebuilt server until its restore (the backup refuses its empty databases). The script makes the status directory `0755` and the file `0644`; they hold no data, and the backup sets stay `0700`. Point the uptime monitor that watches `/health` at an alert you will see.

`/health` also reports the release files: it fails when the binary of the newest release, or of the release a running rollout is sending out, is missing from `FLEET_RELEASES_DIR` or has a different size than its database row (an existence and size check only). Its other checks are described in [health-and-jobs.md](health-and-jobs.md). The response names each check as `ok` or `failing` and nothing else; the server log has the detail.

## Restore

To recover a lost server:

1. **Pause deploys.** In GitHub, **Actions > Deploy > ... > Disable workflow**, so a push to `main` cannot start and migrate the app halfway through. (A deploy also refuses while `docker.sh restore` runs.)
2. Bring back the VM and its PostgreSQL container with the role `cmdb` (the separate task that provisions it), with `CREATEDB` granted as for the drill below. Mount the backup location at `FLEET_BACKUP_DIR` again, and set up the GitHub environment again from your copies of the secrets and variables.
3. **Enable the workflow and run Actions > Deploy once, then disable it again**, so the image, the volume, the `fleet-cmdb` container, and the backup scripts are on the VM. The app starts on empty databases and migrates them. The deploy takes no backup, since the old sets are there, and the nightly backup refuses these databases (they hold fewer hosts than the newest set), so the good sets stay the newest and none is pruned. `/health` reports the backup as failing until step 4.
4. On the VM, as the deploy user, pick the set (`list` shows each set's time and counts), stop the app, drop the four new databases (they hold only the empty schema), and restore:

   ```sh
   B=~/.local/share/fleet-cmdb/backup/docker.sh
   $B list                                         # for example fleet-cmdb-20261116T023112Z  12M  hosts=40 audit_entries=913 ...
   docker stop fleet-cmdb-jobs fleet-cmdb          # fleet-cmdb-jobs exists only with FLEET_JOBS_CONTAINER=true
   for db in cmdb_production cmdb_production_queue cmdb_production_cache cmdb_production_cable; do
     docker exec postgres dropdb -U postgres "$db"
   done
   $B restore fleet-cmdb-20261116T023112Z          # restores, then backs up the restored state
   docker start fleet-cmdb                         # and fleet-cmdb-jobs
   ```

   The `dropdb` lines assume the PostgreSQL container is named `postgres` with the superuser `postgres`; use your own names. `restore.sh` never drops anything itself: it creates missing databases, reuses ones that hold nothing of their own (objects of extensions do not count), and refuses any that holds a table, sequence, view, function, or type. The release directory in the volume must be empty too, as it is on a new VM. `docker.sh restore` also refuses a set that holds no host and no audit entry (the backup of an empty server) unless you add `--force`.
5. **Enable the Deploy workflow again.**

`restore.sh` verifies the checksums and restores each dump into its database with `pg_restore --exit-on-error --single-transaction`, so each database is restored whole or not at all. If one fails, it drops the databases it created and names those that existed before and are now restored, to drop before trying again. Then it unpacks the release files into the empty directory. `docker.sh restore` then backs up the restored state at once, under the same lock, so it becomes the newest set and `/health` turns healthy. On start, `db:prepare` applies any newer migrations. Agents need nothing: their credentials are in the database and they reconnect on their next heartbeat. Deploy CI rehearses these steps, in this order, on every change to the deployment.

**Restoring to roll back** (for example after a migration the old code cannot run on) works the same way, but loses everything written since that backup: hosts enrolled, reports, audit entries, and task results. The restored queue database also brings back the jobs that were pending when the set was taken, and they run again.

## The restore drill

The drill restores a backup set into **scratch** databases (all four) and a scratch release volume, then boots the deployed image against the scratch **primary** and checks the result. The queue, cache, and cable dumps are proven by restoring them; the app's queue and cable connections stay the live ones, but the drill enqueues no job and opens no cable, and it sets `FLEET_RESTORE_DRILL=1`, which swaps the live Solid Cache database for an in-process store. So it writes nothing live, and it removes its scratch data afterwards.

The drill creates databases, so the role `cmdb` needs `CREATEDB`. Grant it once, as a PostgreSQL superuser, in the PostgreSQL container (its provisioning is a separate task): `ALTER ROLE cmdb CREATEDB;`. Without it the drill stops and says so. Then, on the VM as the deploy user:

```sh
~/.local/share/fleet-cmdb/backup/docker.sh restore-drill                               # the newest set
~/.local/share/fleet-cmdb/backup/docker.sh restore-drill fleet-cmdb-20261116T023112Z   # or a chosen one
```

It prints the set's counts first. With no set named, it refuses a newest set that holds no host and no audit entry (the backup of an empty server): name the set to drill. It restores with the backup's PostgreSQL image, then runs `bin/rails backup:verify_restore` in the image of the `fleet-cmdb` container, with that container's settings (read into a mode-0600 file that is removed afterwards). Without the deployment, run `ops/backup/restore-drill.sh` from the app directory with the server's environment instead.

**Disk space.** The scratch databases are a second full copy of the four databases. The drill prints how much space they need (the live databases' size) before it restores. By default they go to the live PostgreSQL server, whose disk must have that much free, and the restore competes with live traffic for I/O. That is fine at homelab size. Once the database is large, set `FLEET_BACKUP_DRILL_HOST` to another PostgreSQL server on the same Docker network (for example a second container just for drills), with a role `cmdb` that has the same password and `CREATEDB`. The scratch databases then go there, and the app boots against them there.

It prints one line per check and exits non-zero if any fails:

- the app boots against the restored database (`/up` answers 200);
- hosts and audit entries are present, and no fewer than `counts` recorded;
- at least as many hosts have an inventory snapshot as `counts` recorded (retention keeps each host's newest snapshot, so this never goes down);
- release rows are present and every one has its binary on disk with the recorded size and SHA-256;
- the newest release downloads through the agent API (`/api/v1/releases/<version>/binary`) and matches its SHA-256.

Deploy CI runs the drill this way on every change to the deployment, with an uploaded release in its data, and once against a second PostgreSQL server. Run it yourself after setting up backups, after any change to the procedure, and on a schedule (quarterly is a reasonable habit); record the date and result below and on [#138](https://github.com/hostilecity/fleet-cmdb/issues/138).

### Drill record

| Date | Backup set | Result | Notes |
|---|---|---|---|
| 2026-11-02 | Sandbox, `fleet-cmdb-20261102T130741Z` (2 hosts, 3 audit entries, 1 uploaded release) | Passed (6 of 6 checks) | PostgreSQL 16, production environment, scratch database and directory removed afterwards. Not yet run on the real server stack. |
| | Deployed server, first drill | | To be run by the owner after the first backup (#138). Deploy CI runs the same drill against the deployed setup on every change. |
