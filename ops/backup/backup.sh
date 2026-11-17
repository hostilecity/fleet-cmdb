#!/usr/bin/env bash
# Scheduled backup of the fleet-cmdb server (P1-O01, docs/operations/backup-and-restore.md).
#
# Writes one backup set, a directory fleet-cmdb-<UTC time>/ in BACKUP_DIR, holding:
#   fleet-cmdb.dump   pg_dump custom-format dump of the primary database (hosts, snapshots, audit log, releases' rows)
#   queue.dump, cache.dump, cable.dump
#                     dumps of the Solid Queue, Solid Cache, and Solid Cable databases (<primary>_queue and so on)
#   releases.tar      the release files in FLEET_RELEASES_DIR (uploaded releases cannot be re-imported from GitHub)
#   counts            row counts taken just before the dump, which the restore drill compares against
#   SHA256SUMS        checksums of the files above
# then prunes old sets and, last of all, touches FLEET_BACKUP_STATUS_FILE, which /health watches. A backup that
# fails part-way therefore leaves the status file alone and /health turns unhealthy once it is old enough.
#
# Needs pg_dump, pg_restore, psql, tar, sha256sum. The database is reached with the standard libpq variables
# (PGHOST, PGPORT, PGUSER, PGPASSWORD or PGPASSFILE, PGDATABASE is ignored: see BACKUP_DB_NAME). pg_dump must be the
# server's major version or newer; the script checks this first and names both versions if not.
#
# In the deployment (.github/workflows/cd.yml) it runs inside a throwaway postgres container on the database's Docker
# network, started by ops/backup/docker.sh, which checks BACKUP_DIR on the VM first (docs/operations/backup-and-restore.md).
#
#   BACKUP_DIR               required: an off-machine location mounted here (NFS, SMB, sshfs, a rclone mount). The
#                            script refuses a directory that is not a mount point unless BACKUP_ALLOW_LOCAL=1.
#   FLEET_RELEASES_DIR       required: the release files (the same variable the server reads)
#   FLEET_BACKUP_STATUS_FILE required: touched after a complete backup (the same variable the server reads)
#   BACKUP_DB_NAME           default cmdb_production; the other three are <name>_queue, <name>_cache, <name>_cable
#   BACKUP_RETENTION_DAYS    default 14: sets older than this are deleted, but the newest BACKUP_KEEP_MIN are kept
#   BACKUP_KEEP_MIN          default 3
set -euo pipefail
umask 077 # backups hold the whole inventory and audit log

die() { echo "backup: $*" >&2; exit 1; }
log() { echo "backup: $*"; }

: "${BACKUP_DIR:?set BACKUP_DIR to the off-machine backup location}"
: "${FLEET_RELEASES_DIR:?set FLEET_RELEASES_DIR}"
: "${FLEET_BACKUP_STATUS_FILE:?set FLEET_BACKUP_STATUS_FILE}"
db="${BACKUP_DB_NAME:-cmdb_production}"
retention_days="${BACKUP_RETENTION_DAYS:-14}"
keep_min="${BACKUP_KEEP_MIN:-3}"

[ -d "$BACKUP_DIR" ] || die "BACKUP_DIR $BACKUP_DIR does not exist"
if [ "${BACKUP_ALLOW_LOCAL:-}" != 1 ] && ! mountpoint -q "$BACKUP_DIR"; then
  die "BACKUP_DIR $BACKUP_DIR is not a mount point, so it may be on this machine. Mount the off-machine location there (or set BACKUP_ALLOW_LOCAL=1 for a test)"
fi

# pg_dump refuses a newer server anyway; say plainly which versions met, and which image setting fixes it.
server_major="$(psql --no-psqlrc -X -At -v ON_ERROR_STOP=1 -d "$db" -c "SELECT current_setting('server_version_num')::int / 10000")"
client_major="$(pg_dump --version | sed -n 's/^pg_dump (PostgreSQL) \([0-9]*\).*/\1/p')"
[[ "$server_major" =~ ^[0-9]+$ && "$client_major" =~ ^[0-9]+$ ]] || die "could not read the PostgreSQL versions (server '$server_major', pg_dump '$client_major')"
if [ "$client_major" -lt "$server_major" ]; then
  die "pg_dump is PostgreSQL $client_major but the server is PostgreSQL $server_major: use a client of version $server_major or newer (in the deployment, the variable FLEET_BACKUP_PG_IMAGE, for example postgres:$server_major)"
fi
log "PostgreSQL server $server_major, pg_dump $client_major"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DIR/fleet-cmdb-$stamp"
work="$BACKUP_DIR/.incoming-$stamp"
[ ! -e "$final" ] || die "$final already exists"
mkdir "$work"
trap 'rm -rf "$work"' EXIT

# Counts first, then the dump: the restore must hold at least these. Hosts, audit entries, and release rows are
# never deleted. Inventory snapshots are pruned, but retention keeps each host's newest one, so the number of hosts
# with a snapshot never goes down. Each count is its own assignment so a failed query stops the backup (an
# `echo "$(...)"` would hide the failure from set -e).
count() {
  local value
  value="$(psql --no-psqlrc -X -At -v ON_ERROR_STOP=1 -d "$db" -c "$1")"
  [[ "$value" =~ ^[0-9]+$ ]] || die "count query returned '$value': $1"
  printf '%s' "$value"
}
hosts="$(count "SELECT count(*) FROM hosts")"
audit_entries="$(count "SELECT count(*) FROM audit_entries")"
agent_releases="$(count "SELECT count(*) FROM agent_releases")"
hosts_with_inventory="$(count "SELECT count(DISTINCT host_id) FROM inventory_snapshots")"
printf 'hosts=%s\naudit_entries=%s\nagent_releases=%s\nhosts_with_inventory=%s\n' \
  "$hosts" "$audit_entries" "$agent_releases" "$hosts_with_inventory" > "$work/counts"

# The primary database, then the queue, cache, and cable databases. Each dump must read back.
dump() {
  pg_dump --format=custom --no-owner --no-privileges --file "$work/$2" "$1"
  pg_restore --list "$work/$2" > /dev/null
}
dump "$db" fleet-cmdb.dump
for side in queue cache cable; do dump "${db}_$side" "$side.dump"; done

if [ -d "$FLEET_RELEASES_DIR" ]; then
  tar -C "$FLEET_RELEASES_DIR" -cf "$work/releases.tar" .
elif [ "$agent_releases" -eq 0 ]; then
  tar -cf "$work/releases.tar" -T /dev/null # no release was ever stored: an empty archive
else
  # The database names releases whose files are missing. Uploaded releases cannot be re-imported, so stop before
  # publishing this set, pruning older ones, or touching the status file: /health turns unhealthy.
  die "FLEET_RELEASES_DIR $FLEET_RELEASES_DIR does not exist, but the database has $agent_releases release(s)"
fi

(cd "$work" && sha256sum fleet-cmdb.dump queue.dump cache.dump cable.dump releases.tar counts > SHA256SUMS)
mv "$work" "$final" # a set appears whole or not at all
trap - EXIT
log "wrote $final ($(du -sh "$final" | cut -f1))"

# Retention: delete sets older than the window, never the newest keep_min.
mapfile -t sets < <(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'fleet-cmdb-*' | sort -r)
for i in "${!sets[@]}"; do
  [ "$i" -lt "$keep_min" ] && continue
  if [ -n "$(find "${sets[$i]}" -maxdepth 0 -mtime "+$retention_days")" ]; then
    rm -rf "${sets[$i]}"
    log "pruned ${sets[$i]}"
  fi
done

# The server (a non-root user in its container) only needs to stat the status file, but umask 077 would make a
# new directory 0700 and hide it. The status directory and file hold no data, so they are made readable to all;
# the backup sets themselves stay private.
status_dir="$(dirname "$FLEET_BACKUP_STATUS_FILE")"
mkdir -p "$status_dir"
chmod 0755 "$status_dir"
touch "$FLEET_BACKUP_STATUS_FILE"
chmod 0644 "$FLEET_BACKUP_STATUS_FILE"
log "done"
