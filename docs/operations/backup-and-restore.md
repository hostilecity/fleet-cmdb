# Backup and restore (P1-O01, NFR-2)

A backup that has never been restored is not a backup. This page says what is backed up, what is not, how to schedule it, how to restore, and how to prove it works (the restore drill). The scripts are in [`ops/backup/`](../../ops/backup/). Hostnames below are placeholders (`vm-01.example.lan`, `backup-01.example.lan`).

## What is backed up

| Data | In the backup set? | Why |
|---|---|---|
| Primary database (`cmdb_production`): hosts, snapshots, status history, the audit log, operators, release rows, settings | Yes, `fleet-cmdb.dump` (`pg_dump`, custom format) | Everything the fleet knows. |
| Release files (`FLEET_RELEASES_DIR`, `storage/releases` by default) | Yes, `releases.tar` | An uploaded release cannot be re-imported from GitHub, and the database rows are checked against these files. Imported releases could be re-imported, but one tar covers both. |
| Queue, cache, and cable databases | No | Rebuilt by `db:prepare`; the queue only holds jobs, and recurring jobs come back from `config/recurring.yml`. A pending import is lost and can be started again. |
| Row counts | Yes, `counts` | Taken just before the dump; the drill checks the restore holds at least this many hosts, audit entries, releases, and hosts with an inventory snapshot. A count query that fails stops the backup. |

Each run writes one directory, `fleet-cmdb-<UTC time>/`, with the files above and `SHA256SUMS`. It appears whole or not at all.

**Back up separately, never in this set and never in git** (the dump contains the whole inventory and audit log, and none of these):

- the Rails master key (`config/master.key`) or `RAILS_MASTER_KEY`, and `SECRET_KEY_BASE` if set;
- `FLEET_ENCRYPTION_KEY`: the dump holds operators' second-factor keys only encrypted with it, and recovery codes only as HMACs keyed from it. A restore without it works, but every operator's second factor must be reset (`bin/rails second_factor:reset EMAIL=…`) and set up again;
- the environment file: hostnames, `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, `DATABASE_PASSWORD`, the release public keys (`FLEET_RELEASE_KEY_CURRENT`, `FLEET_RELEASE_KEY_NEXT`);
- the Cloudflare API token (DNS edit for the one zone) and the tunnel credentials;
- the agent hostname certificate state (the proxy's ACME account and certificate volume). It can be re-issued by the DNS challenge, so losing it costs minutes, not data.

Keep these in a password manager or an encrypted store, not on the same machine as the server. Treat backup sets as sensitive too: restrict the location to the backup account (the scripts write files mode 0600) and encrypt it at rest.

## Schedule it

`ops/backup/backup.sh` runs on the server machine (it needs `pg_dump`, `pg_restore`, `psql`, `tar`, `sha256sum`).

1. Mount an **off-machine** location at a fixed path, for example an NFS or SMB share on `backup-01.example.lan` at `/mnt/fleet-cmdb-backups`. The script refuses a directory that is not a mount point, so a backup cannot quietly land on the server's own disk (`BACKUP_ALLOW_LOCAL=1` overrides this for tests only).
2. Copy `ops/backup/backup.env.example` to `/etc/fleet-cmdb/backup.env` (mode 0600) and fill it in. `FLEET_RELEASES_DIR` and `FLEET_BACKUP_STATUS_FILE` must be the host paths of the same volumes the server container uses. If `FLEET_RELEASES_DIR` is missing while the database has release rows, the backup fails rather than writing a set without them.
3. Install the units and start the timer (daily at 02:30 with a random delay):

   ```sh
   sudo install -m 0644 ops/backup/fleet-cmdb-backup.service ops/backup/fleet-cmdb-backup.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now fleet-cmdb-backup.timer
   sudo systemctl start fleet-cmdb-backup.service     # the first backup now
   journalctl -u fleet-cmdb-backup.service -n 20
   ```

**Retention:** sets older than `BACKUP_RETENTION_DAYS` (14) are deleted after a successful run, but the newest `BACKUP_KEEP_MIN` (3) are always kept, so a long outage cannot prune the last good backups.

## Know when backups stop

After a complete backup the script touches `FLEET_BACKUP_STATUS_FILE`. `GET /health` (agent hostname or localhost) reports the backup check as failing, and the whole endpoint as 503, when that file is missing or older than `FLEET_BACKUP_MAX_AGE_HOURS` (26). A fresh install therefore reports unhealthy until its first backup. The script makes the status directory `0755` and the file `0644` so the server's non-root user can see it; they hold no data, and the backup sets stay `0700`. Point the uptime monitor that watches `/health` at an alert you will see. A new install is unhealthy until its first backup, which is deliberate: run the first backup straight after deploying.

`/health` also reports the release files: it fails when the binary of the newest release, or of the release a running rollout is sending out, is missing from `FLEET_RELEASES_DIR` or has a different size than its database row (an existence and size check only). Its other checks are described in [health-and-jobs.md](health-and-jobs.md). The response names each check as `ok` or `failing` and nothing else; the server log has the detail.

## Restore

To recover a lost server, bring up a new PostgreSQL server and empty volumes, restore the secrets above, then:

```sh
ops/backup/restore.sh /mnt/fleet-cmdb-backups/fleet-cmdb-<time> cmdb_production /var/lib/fleet-cmdb/releases
```

`restore.sh` verifies the checksums, creates the database (it refuses one that exists), restores it with `pg_restore --exit-on-error` (dropping it again if that fails), and unpacks the release files into an empty directory. Then start the stack (`db:prepare` creates the queue, cache, and cable databases and applies any newer migrations), and run the drill checks below against production data if you want a receipt. Agents need nothing: their credentials are in the database and they reconnect on their next heartbeat. The agent hostname certificate is re-issued automatically if its state was lost.

## The restore drill

The drill restores the newest backup set into a **scratch** database and release directory, boots the app against them, and checks the result. It changes nothing live and removes its scratch data afterwards: it sets `FLEET_RESTORE_DRILL=1`, which swaps the live Solid Cache database for an in-process store, so its requests write no rate-limit counters to the live cache.

Run it with the server's environment (the same variables the app runs with, plus the libpq variables for a role that may create databases), from the app directory:

```sh
BACKUP_DIR=/mnt/fleet-cmdb-backups RAILS_ENV=production ops/backup/restore-drill.sh
# or a chosen set: ops/backup/restore-drill.sh /mnt/fleet-cmdb-backups/fleet-cmdb-<time>
```

It prints one line per check and exits non-zero if any fails:

- the app boots against the restored database (`/up` answers 200);
- hosts and audit entries are present, and no fewer than `counts` recorded;
- at least as many hosts have an inventory snapshot as `counts` recorded (retention keeps each host's newest snapshot, so this never goes down);
- release rows are present and every one has its binary on disk with the recorded size and SHA-256;
- the newest release downloads through the agent API (`/api/v1/releases/<version>/binary`) and matches its SHA-256.

Run the drill after setting up backups, after any change to the procedure, and on a schedule (quarterly is a reasonable habit); record the date and result in the Phase 1 delivery note.

### Drill record

| Date | Backup set | Result | Notes |
|---|---|---|---|
| 2026-11-02 | Sandbox, `fleet-cmdb-20261102T130741Z` (2 hosts, 3 audit entries, 1 uploaded release) | Passed (6 of 6 checks) | PostgreSQL 16, production environment, scratch database and directory removed afterwards. Not yet run on the real server stack (compose deployment, P1-O03). |
