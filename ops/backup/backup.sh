#!/usr/bin/env bash
# Scheduled backup of the fleet-cmdb server (P1-O01, docs/operations/backup-and-restore.md).
#
# Writes one backup set, a directory fleet-cmdb-<UTC time>/ in BACKUP_DIR, holding:
#   fleet-cmdb.dump   pg_dump custom-format dump of the primary database (hosts, snapshots, audit log, releases' rows)
#   releases.tar      the release files in FLEET_RELEASES_DIR (uploaded releases cannot be re-imported from GitHub)
#   counts            row counts taken just before the dump, which the restore drill compares against
#   SHA256SUMS        checksums of the three files above
# then prunes old sets and, last of all, touches FLEET_BACKUP_STATUS_FILE, which /health watches. A backup that
# fails part-way therefore leaves the status file alone and /health turns unhealthy once it is old enough.
#
# Needs pg_dump, pg_restore, psql, tar, sha256sum. The database is reached with the standard libpq variables
# (PGHOST, PGUSER, PGPASSWORD or PGPASSFILE, PGDATABASE is ignored: see BACKUP_DB_NAME).
#
#   BACKUP_DIR               required: an off-machine location mounted here (NFS, SMB, sshfs, a rclone mount). The
#                            script refuses a directory that is not a mount point unless BACKUP_ALLOW_LOCAL=1.
#   FLEET_RELEASES_DIR       required: the release files (the same variable the server reads)
#   FLEET_BACKUP_STATUS_FILE required: touched after a complete backup (the same variable the server reads)
#   BACKUP_DB_NAME           default cmdb_production
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

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DIR/fleet-cmdb-$stamp"
work="$BACKUP_DIR/.incoming-$stamp"
[ ! -e "$final" ] || die "$final already exists"
mkdir "$work"
trap 'rm -rf "$work"' EXIT

# Counts first, then the dump: the restore must hold at least these (rows are only ever added, never removed).
for table in hosts audit_entries agent_releases; do
  echo "$table=$(psql --no-psqlrc -X -At -d "$db" -c "SELECT count(*) FROM $table")"
done > "$work/counts"

pg_dump --format=custom --no-owner --no-privileges --file "$work/fleet-cmdb.dump" "$db"
pg_restore --list "$work/fleet-cmdb.dump" > /dev/null # the dump can be read back

if [ -d "$FLEET_RELEASES_DIR" ]; then
  tar -C "$FLEET_RELEASES_DIR" -cf "$work/releases.tar" .
else
  tar -cf "$work/releases.tar" -T /dev/null # no release was ever stored: an empty archive
fi

(cd "$work" && sha256sum fleet-cmdb.dump releases.tar counts > SHA256SUMS)
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

mkdir -p "$(dirname "$FLEET_BACKUP_STATUS_FILE")"
touch "$FLEET_BACKUP_STATUS_FILE"
log "done"
