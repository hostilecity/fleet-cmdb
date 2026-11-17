#!/usr/bin/env bash
# The restore drill (P1-O01): restore a backup set into scratch databases (the primary, and its queue, cache, and
# cable databases) and a scratch release directory, boot the app against the primary, and check that hosts, the
# audit log, and release downloads are there. Nothing live is touched. In the deployment, run
# `ops/backup/docker.sh restore-drill` on the VM instead: it does the same with containers.
#
#   restore-drill.sh [backup set directory]     (default: the newest set in BACKUP_DIR)
#
# Run it from the server's app directory (the cmdb/ directory, or /rails in the container) with the same
# environment as the server (RAILS_ENV=production, SECRET_KEY_BASE or the master key, FLEET_ENCRYPTION_KEY, FLEET_DASHBOARD_HOST,
# FLEET_AGENT_HOST, the libpq variables, DATABASE_PASSWORD), so the app boots exactly as it does in
# production. Exit status 0 means the drill passed. Set DRILL_KEEP=1 to keep the scratch database and files.
set -euo pipefail

ops="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set_dir="${1:-}"
if [ -z "$set_dir" ]; then
  : "${BACKUP_DIR:?give a backup set directory or set BACKUP_DIR}"
  set_dir="$(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'fleet-cmdb-*' | sort | tail -n 1)"
  [ -n "$set_dir" ] || { echo "restore drill: no backup set in $BACKUP_DIR" >&2; exit 1; }
fi

scratch_db="cmdb_restore_drill_$(date -u +%Y%m%d%H%M%S)_$$"
scratch_dir="$(mktemp -d)"
cleanup() {
  if [ "${DRILL_KEEP:-}" = 1 ]; then
    echo "restore drill: kept the databases $scratch_db(_queue, _cache, _cable) and $scratch_dir"
  else
    for name in "$scratch_db" "${scratch_db}_queue" "${scratch_db}_cache" "${scratch_db}_cable"; do
      dropdb --if-exists "$name" || true
    done
    rm -rf "$scratch_dir"
  fi
}
trap cleanup EXIT

echo "restore drill: restoring $set_dir"
"$ops/restore.sh" "$set_dir" "$scratch_db" "$scratch_dir/releases"

# The app reads the scratch database (DATABASE_URL replaces the primary database only) and the scratch release files.
# FLEET_RESTORE_DRILL=1 swaps the Solid Cache store for an in-process memory store (config/environments/production.rb),
# so the drill's requests never write rate-limit counters into the live cache database. The drill enqueues no jobs
# and opens no Action Cable connection, so the queue and cable databases are not touched either.
FLEET_RESTORE_DRILL=1 DATABASE_URL="postgresql:///$scratch_db" FLEET_RELEASES_DIR="$scratch_dir/releases" \
  COUNTS="$set_dir/counts" bin/rails backup:verify_restore
