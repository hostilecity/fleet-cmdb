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
# A database that is not the one backed up before is refused (#138): hosts and audit entries are never deleted, so
# if this database has fewer of either than the newest set recorded, it is a new or replaced one (for example the
# empty databases of a rebuilt server). Writing its set would make an empty set the newest one and let retention
# prune the good ones, so nothing is written, the status file is left alone, and /health turns unhealthy. Set
# BACKUP_FORCE=1 to back it up anyway: after deliberately restoring an older set, or after a deliberate fresh start
# with an emptied database. The forced set becomes the newest, so later backups compare against it. The guard
# relies on hosts and audit entries never being deleted (FR-S.3, ADR 0027 decision 7).
#
# Needs pg_dump, pg_restore, psql, tar, sha256sum, GNU date. The database is reached with the standard libpq
# variables (PGHOST, PGPORT, PGUSER, PGPASSWORD or PGPASSFILE, PGDATABASE is ignored: see BACKUP_DB_NAME). pg_dump
# must be the server's major version or newer; the script checks this first and names both versions if not.
#
# In the deployment (.github/workflows/cd.yml) it runs inside a throwaway postgres container on the database's Docker
# network, started by ops/backup/docker.sh, which checks BACKUP_DIR on the VM, holds the backup lock, and touches the
# status file itself afterwards (so this container never writes to the app's volume).
#
#   BACKUP_DIR               required: an off-machine location mounted here (NFS, SMB, sshfs, a rclone mount). The
#                            script refuses a directory that is not a mount point unless BACKUP_ALLOW_LOCAL=1.
#   FLEET_RELEASES_DIR       required: the release files (the same variable the server reads)
#   FLEET_BACKUP_STATUS_FILE touched after a complete backup (the same variable the server reads); required unless
#                            BACKUP_NO_STATUS=1, which leaves it to the caller
#   BACKUP_DB_NAME           default cmdb_production; the other three are <name>_queue, <name>_cache, <name>_cable
#   BACKUP_RETENTION_DAYS    default 14: sets older than this (by the time in their name) are deleted, but the newest
#                            BACKUP_KEEP_MIN are always kept, and so is the newest set holding more hosts or more
#                            audit entries than the newest set (the last set of an earlier, bigger database, after
#                            a forced backup), until deleted by hand (docker.sh delete); its older ones age out
#   BACKUP_KEEP_MIN          default 3
#   BACKUP_FORCE             1: write the set even if the database holds fewer hosts or audit entries (see above)
set -euo pipefail
umask 077 # backups hold the whole inventory and audit log

die() { echo "backup: $*" >&2; exit 1; }
log() { echo "backup: $*"; }

: "${BACKUP_DIR:?set BACKUP_DIR to the off-machine backup location}"
: "${FLEET_RELEASES_DIR:?set FLEET_RELEASES_DIR}"
if [ "${BACKUP_NO_STATUS:-}" != 1 ]; then : "${FLEET_BACKUP_STATUS_FILE:?set FLEET_BACKUP_STATUS_FILE}"; fi
db="${BACKUP_DB_NAME:-cmdb_production}"
retention_days="${BACKUP_RETENTION_DAYS:-14}"
keep_min="${BACKUP_KEEP_MIN:-3}"
[[ "$retention_days" =~ ^[0-9]+$ && "$keep_min" =~ ^[0-9]+$ ]] || die "BACKUP_RETENTION_DAYS and BACKUP_KEEP_MIN must be whole numbers"

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

# Sets newest first, by name (the name holds the UTC time it was taken).
sets_newest_first() { find "$BACKUP_DIR" -maxdepth 1 -type d -name 'fleet-cmdb-*' | sort -r; }
count_in() { sed -n "s/^$2=\([0-9]*\)$/\1/p" "$1/counts" 2> /dev/null; }

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
log "hosts=$hosts audit_entries=$audit_entries agent_releases=$agent_releases"

# Never let a new or replaced database displace the sets of the real one (see the top).
newest="$(sets_newest_first | head -n 1)"
if [ -n "$newest" ] && [ "${BACKUP_FORCE:-}" != 1 ]; then
  last_hosts="$(count_in "$newest" hosts)" last_audit="$(count_in "$newest" audit_entries)"
  if [ -n "$last_hosts" ] && [ -n "$last_audit" ] && { [ "$hosts" -lt "$last_hosts" ] || [ "$audit_entries" -lt "$last_audit" ]; }; then
    die "refused: the database holds $hosts hosts and $audit_entries audit entries, fewer than the newest set $(basename "$newest") ($last_hosts and $last_audit). Hosts and audit entries are never deleted, so this is not the database that was backed up (for example the empty databases of a rebuilt server: restore a set first, docs/operations/backup-and-restore.md). Nothing was written and no set was pruned. If the server was lost, restore a set first. If you restored an older set on purpose, or emptied the database on purpose for a fresh start, back up with BACKUP_FORCE=1 (docker.sh backup --force): the new set becomes the one later backups compare against, and the newest older set that holds more is kept until you delete it"
  fi
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DIR/fleet-cmdb-$stamp"
work="$BACKUP_DIR/.incoming-$stamp"
[ ! -e "$final" ] || die "$final already exists"
mkdir "$work"
trap 'rm -rf "$work"' EXIT
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

# Retention: delete sets older than the window, by the UTC time in their name (a mount's mtimes may not be kept),
# but never the newest keep_min, and never the newest set that holds more hosts or more audit entries than the one
# just written: the last set of an earlier, bigger database (after a forced backup), kept until deleted by hand. Its
# older sets are pruned by age as usual: one copy is enough to go back to.
now="$(date -u +%s)"
age_of() { # seconds since the UTC time in a fleet-cmdb-<time> or .incoming-<time> name, or nothing
  local t="${1##*-}"
  [[ "$t" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]] || return 0
  echo $((now - $(date -u -d "${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}" +%s)))
}
mapfile -t sets < <(sets_newest_first)
bigger=""
for set in "${sets[@]}"; do
  set_hosts="$(count_in "$set" hosts)" set_audit="$(count_in "$set" audit_entries)"
  if [ "${set_hosts:-0}" -gt "$hosts" ] || [ "${set_audit:-0}" -gt "$audit_entries" ]; then bigger="$set"; break; fi
done
for i in "${!sets[@]}"; do
  [ "$i" -lt "$keep_min" ] && continue
  if [ "${sets[$i]}" = "$bigger" ]; then
    log "kept ${sets[$i]}: the newest set that holds more than this one (delete it by hand when it is no longer needed)"
    continue
  fi
  age="$(age_of "$(basename "${sets[$i]}")")"
  if [ -n "$age" ] && [ "$age" -gt $((retention_days * 86400)) ]; then
    rm -rf "${sets[$i]}"
    log "pruned ${sets[$i]}"
  fi
done
# A run that was killed leaves its .incoming-<time> directory; remove those more than a day old, by that time.
while IFS= read -r stale; do
  age="$(age_of "$(basename "$stale")")"
  if [ -n "$age" ] && [ "$age" -gt 86400 ]; then
    rm -rf "$stale"
    log "removed $stale, left by an interrupted run"
  fi
done < <(find "$BACKUP_DIR" -maxdepth 1 -type d -name '.incoming-*')

if [ "${BACKUP_NO_STATUS:-}" = 1 ]; then log "done"; exit 0; fi
# The server (a non-root user in its container) only needs to stat the status file, but umask 077 would make a
# new directory 0700 and hide it. The status directory and file hold no data, so they are made readable to all;
# the backup sets themselves stay private.
status_dir="$(dirname "$FLEET_BACKUP_STATUS_FILE")"
mkdir -p "$status_dir"
chmod 0755 "$status_dir"
touch "$FLEET_BACKUP_STATUS_FILE"
chmod 0644 "$FLEET_BACKUP_STATUS_FILE"
log "done"
