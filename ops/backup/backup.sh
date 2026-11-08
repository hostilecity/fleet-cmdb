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
# (PGHOST, PGPORT, PGUSER, PGPASSWORD or PGPASSFILE, PGDATABASE is ignored: see BACKUP_DB_NAME).
#
# A PostgreSQL container that publishes no port (an existing PostgreSQL Compose project): set FLEET_DB_NETWORK to its
# Docker network and PGHOST to its name there. The script then checks BACKUP_DIR on this machine and runs itself in
# a throwaway BACKUP_IMAGE container on that network, with the same paths mounted, so this machine needs Docker
# but no PostgreSQL client, and the PostgreSQL project needs no change. PGPASSFILE is not passed in this mode.
#
#   FLEET_DB_NETWORK         optional: the database container's Docker network (see above)
#   BACKUP_IMAGE             default postgres:17: its pg_dump must be the server's major version or newer
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

# In a container on the database's network (see the top). BACKUP_DIR was checked above, on this machine: inside the
# container every bind mount is a mount point, so the check is skipped there.
if [ -n "${FLEET_DB_NETWORK:-}" ] && [ "${BACKUP_IN_CONTAINER:-}" != 1 ]; then
  ops="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  status_dir="$(dirname "$FLEET_BACKUP_STATUS_FILE")"
  mkdir -p "$status_dir"
  mounts=(-v "$ops:$ops:ro" -v "$BACKUP_DIR:$BACKUP_DIR" -v "$status_dir:$status_dir")
  # Only an existing release directory: Docker would otherwise create it, owned by root, and the app could not
  # write to it. Without it the script below fails if the database names releases, as it does on this machine.
  if [ -d "$FLEET_RELEASES_DIR" ]; then mounts+=(-v "$FLEET_RELEASES_DIR:$FLEET_RELEASES_DIR:ro"); fi
  log "running in ${BACKUP_IMAGE:-postgres:17} on the Docker network $FLEET_DB_NETWORK"
  # -e NAME passes a variable only if it is set here, and never puts its value on the command line.
  exec docker run --rm --network "$FLEET_DB_NETWORK" "${mounts[@]}" \
    -e BACKUP_IN_CONTAINER=1 -e BACKUP_ALLOW_LOCAL=1 -e BACKUP_DIR -e FLEET_RELEASES_DIR -e FLEET_BACKUP_STATUS_FILE \
    -e BACKUP_DB_NAME -e BACKUP_RETENTION_DAYS -e BACKUP_KEEP_MIN -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD \
    -e PGSSLMODE --entrypoint bash "${BACKUP_IMAGE:-postgres:17}" "$ops/backup.sh"
fi

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

pg_dump --format=custom --no-owner --no-privileges --file "$work/fleet-cmdb.dump" "$db"
pg_restore --list "$work/fleet-cmdb.dump" > /dev/null # the dump can be read back

if [ -d "$FLEET_RELEASES_DIR" ]; then
  tar -C "$FLEET_RELEASES_DIR" -cf "$work/releases.tar" .
elif [ "$agent_releases" -eq 0 ]; then
  tar -cf "$work/releases.tar" -T /dev/null # no release was ever stored: an empty archive
else
  # The database names releases whose files are missing. Uploaded releases cannot be re-imported, so stop before
  # publishing this set, pruning older ones, or touching the status file: /health turns unhealthy.
  die "FLEET_RELEASES_DIR $FLEET_RELEASES_DIR does not exist, but the database has $agent_releases release(s)"
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

# The server (a non-root user in its container) only needs to stat the status file, but umask 077 would make a
# new directory 0700 and hide it. The status directory and file hold no data, so they are made readable to all;
# the backup sets themselves stay private.
status_dir="$(dirname "$FLEET_BACKUP_STATUS_FILE")"
mkdir -p "$status_dir"
chmod 0755 "$status_dir"
touch "$FLEET_BACKUP_STATUS_FILE"
chmod 0644 "$FLEET_BACKUP_STATUS_FILE"
log "done"
