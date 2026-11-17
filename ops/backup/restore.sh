#!/usr/bin/env bash
# Restores a backup set (ops/backup/backup.sh) into new or empty databases and an empty release directory (P1-O01).
#
#   restore.sh <backup set directory> <database name> <release directory>
#
# The primary dump goes into <database name>, and the queue, cache, and cable dumps (when the set has them) into
# <database name>_queue, _cache, and _cable. Each database is created, or reused only if it exists and holds no
# table yet (as a freshly provisioned PostgreSQL has them). It refuses a database that holds any table and a
# non-empty release directory, so it cannot overwrite live data. To recover a lost server, run it under the
# production database name with the app stopped (in the deployment: ops/backup/docker.sh restore), then start the
# app (docs/operations/backup-and-restore.md). The restore drill runs it against scratch names.
# Needs createdb, dropdb, pg_restore, psql, tar, sha256sum, and the libpq variables (PGHOST, PGUSER, PGPASSWORD).
set -euo pipefail

die() { echo "restore: $*" >&2; exit 1; }
sql() { psql --no-psqlrc -X -At -v ON_ERROR_STOP=1 "$@"; }

[ "$#" -eq 3 ] || die "usage: restore.sh <backup set directory> <database name> <release directory>"
set_dir="$1" db="$2" releases_dir="$3"
[ -d "$set_dir" ] || die "$set_dir is not a directory"
# 57 characters at most, so the _queue, _cache, and _cable names stay within PostgreSQL's 63.
[[ "$db" =~ ^[a-z][a-z0-9_]{0,56}$ ]] || die "the database name must be lowercase letters, digits, and underscores (57 at most)"
if [ -d "$releases_dir" ] && [ -n "$(ls -A "$releases_dir")" ]; then die "$releases_dir is not empty"; fi

(cd "$set_dir" && sha256sum --check --quiet SHA256SUMS) || die "checksum mismatch: this backup set is damaged"

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
    tables="$(sql -d "$name" -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'")"
    [ "$tables" = 0 ] || die "database $name already exists and holds data ($tables tables or sequences); nothing was changed"
  fi
done

# Creating a database needs CREATEDB (or a superuser). A PostgreSQL set up with the role owning ready-made databases
# may not have given it: say what to run, rather than createdb's error.
if [ "${#to_create[@]}" -gt 0 ]; then
  role="$(sql -d postgres -c "SELECT current_user || ' ' || (rolcreatedb OR rolsuper)::text FROM pg_roles WHERE rolname = current_user")"
  if [ "${role##* }" != true ]; then
    die "the PostgreSQL role ${role% *} may not create databases, which the restore drill (and a restore into missing databases) needs. Run this once as a PostgreSQL superuser: ALTER ROLE ${role% *} CREATEDB;"
  fi
fi

created=()
undo() {
  for name in "${created[@]}"; do dropdb --if-exists "$name" || true; done
}
for ((i = 0; i < ${#targets[@]}; i += 2)); do
  name="${targets[$i]}" file="${targets[$((i + 1))]}"
  if [[ " ${to_create[*]} " == *" $name "* ]]; then
    createdb "$name"
    created+=("$name")
  fi
  if ! pg_restore --no-owner --no-privileges --exit-on-error --dbname "$name" "$set_dir/$file"; then
    undo
    die "pg_restore of $file into $name failed; the databases this run created were dropped (an existing one it restored into may now be partly filled: drop and re-create it before trying again)"
  fi
  echo "restore: $file restored into $name"
done
mkdir -p "$releases_dir"
tar -C "$releases_dir" -xf "$set_dir/releases.tar"
echo "restore: databases and release files in $releases_dir restored from $set_dir"
