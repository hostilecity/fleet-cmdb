#!/usr/bin/env bash
# Restores a backup set (ops/backup/backup.sh) into new or empty databases and an empty release directory (P1-O01).
#
#   restore.sh <backup set directory> <database name> <release directory>
#
# The primary dump goes into <database name>, and the queue, cache, and cable dumps (when the set has them) into
# <database name>_queue, _cache, and _cable. Each database is created, or reused only if it exists and holds no
# table, sequence, view, function, or type of its own yet (as a freshly provisioned PostgreSQL has them; objects
# of extensions do not count). Each database is restored in one transaction, so it is restored whole or not at all. It refuses a database that holds any table and a
# non-empty release directory, so it cannot overwrite live data. To recover a lost server, run it under the
# production database name with the app stopped (in the deployment: ops/backup/docker.sh restore), then start the
# app (docs/operations/backup-and-restore.md). The restore drill runs it against scratch names.
# Exit status: 0 restored; 64 refused, nothing changed; anything else failed part-way (see the message).
# Needs createdb, dropdb, pg_restore, psql, tar, sha256sum, and the libpq variables (PGHOST, PGUSER, PGPASSWORD).
set -euo pipefail

die() { echo "restore: $*" >&2; exit 1; }
# Exit status 64: refused before anything was changed (ops/backup/docker.sh may then clear its restore marker). No
# tool this script runs returns 64 (psql's ON_ERROR_STOP failure, for one, is 3), so a failure part-way is never
# mistaken for a refusal.
refuse() { echo "restore: $*" >&2; exit 64; }
sql() { psql --no-psqlrc -X -At -v ON_ERROR_STOP=1 "$@"; }

[ "$#" -eq 3 ] || refuse "usage: restore.sh <backup set directory> <database name> <release directory>"
set_dir="$1" db="$2" releases_dir="$3"
[ -d "$set_dir" ] || refuse "$set_dir is not a directory"
# 57 characters at most, so the _queue, _cache, and _cable names stay within PostgreSQL's 63.
[[ "$db" =~ ^[a-z][a-z0-9_]{0,56}$ ]] || refuse "the database name must be lowercase letters, digits, and underscores (57 at most)"
if [ -d "$releases_dir" ] && [ -n "$(ls -A "$releases_dir")" ]; then refuse "$releases_dir is not empty"; fi

(cd "$set_dir" && sha256sum --check --quiet SHA256SUMS) || refuse "checksum mismatch: this backup set is damaged"

# Database name => dump file. Sets from before the queue, cache, and cable dumps hold only the primary.
targets=("$db" fleet-cmdb.dump)
for side in queue cache cable; do
  if [ -f "$set_dir/$side.dump" ]; then targets+=("${db}_$side" "$side.dump"); fi
done

# Check every target before changing anything.
to_create=()
for ((i = 0; i < ${#targets[@]}; i += 2)); do
  name="${targets[$i]}"
  if [ "$(sql -d postgres -c "SELECT count(*) FROM pg_database WHERE datname = '$name'")" = 0 ]; then
    to_create+=("$name")
  else
    # Objects in user schemas that no extension owns: relations, functions, and enum, domain, and range types.
    objects="$(sql -d "$name" -c "
      WITH user_ns AS (SELECT oid FROM pg_namespace WHERE nspname NOT IN ('pg_catalog', 'information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp%'),
           ext AS (SELECT classid, objid FROM pg_depend WHERE deptype = 'e')
      SELECT (SELECT count(*) FROM pg_class c WHERE c.relnamespace IN (SELECT oid FROM user_ns) AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
                AND NOT EXISTS (SELECT 1 FROM ext WHERE ext.classid = 'pg_class'::regclass AND ext.objid = c.oid))
           + (SELECT count(*) FROM pg_proc p WHERE p.pronamespace IN (SELECT oid FROM user_ns)
                AND NOT EXISTS (SELECT 1 FROM ext WHERE ext.classid = 'pg_proc'::regclass AND ext.objid = p.oid))
           + (SELECT count(*) FROM pg_type t WHERE t.typnamespace IN (SELECT oid FROM user_ns) AND t.typtype IN ('e', 'd', 'r', 'm')
                AND NOT EXISTS (SELECT 1 FROM ext WHERE ext.classid = 'pg_type'::regclass AND ext.objid = t.oid))")"
    [ "$objects" = 0 ] || refuse "database $name already exists and holds data ($objects tables, sequences, views, functions, or types); nothing was changed"
  fi
done

# Creating a database needs CREATEDB (or a superuser). A PostgreSQL set up with the role owning ready-made databases
# may not have given it: say what to run, rather than createdb's error.
if [ "${#to_create[@]}" -gt 0 ]; then
  role="$(sql -d postgres -c "SELECT current_user || ' ' || (rolcreatedb OR rolsuper)::text FROM pg_roles WHERE rolname = current_user")"
  if [ "${role##* }" != true ]; then
    refuse "the PostgreSQL role ${role% *} may not create databases, which the restore drill (and a restore into missing databases) needs. Run this once as a PostgreSQL superuser: ALTER ROLE ${role% *} CREATEDB;"
  fi
fi

# The primary dump without the audit log's guard (ADR 0027): its event triggers, which only a superuser can create
# (this runs as the app's role), and the fleet_audit_guard schema with its functions and table, which would otherwise
# come back owned by the app's role. After a real restore the superuser installs the guard again
# (ops/postgres/audit-guard.sql); until then /health shows audit_guard as a warning.
list="$(mktemp)"
trap 'rm -f "$list"' EXIT
pg_restore --list "$set_dir/fleet-cmdb.dump" | grep -v -E ' EVENT TRIGGER | fleet_audit_guard ' > "$list"

created=() restored=()
undo() {
  for name in "${created[@]}"; do dropdb --if-exists "$name" || true; done
}
for ((i = 0; i < ${#targets[@]}; i += 2)); do
  name="${targets[$i]}" file="${targets[$((i + 1))]}"
  if [[ " ${to_create[*]} " == *" $name "* ]]; then
    createdb "$name"
    created+=("$name")
  fi
  use_list=()
  if [ "$file" = fleet-cmdb.dump ]; then use_list=(--use-list "$list"); fi
  if ! pg_restore --no-owner --no-privileges --exit-on-error --single-transaction "${use_list[@]}" --dbname "$name" "$set_dir/$file"; then
    undo
    kept=()
    for done_name in "${restored[@]}"; do [[ " ${created[*]} " == *" $done_name "* ]] || kept+=("$done_name"); done
    message="pg_restore of $file into $name failed, so nothing of it was restored (one transaction). The databases this run created were dropped"
    if [ "${#kept[@]}" -gt 0 ]; then
      message+="; these existed before and are now fully restored: ${kept[*]}. Drop and re-create them (empty) before trying again"
    fi
    die "$message"
  fi
  restored+=("$name")
  echo "restore: $file restored into $name"
done
mkdir -p "$releases_dir"
tar -C "$releases_dir" -xf "$set_dir/releases.tar"
echo "restore: databases and release files in $releases_dir restored from $set_dir"
echo "restore: for a real restore, the PostgreSQL superuser now runs ops/postgres/audit-guard.sql against $db (docs/operations/backup-and-restore.md)"
