#!/usr/bin/env bash
# Restores a backup set (ops/backup/backup.sh) into a NEW database and an empty release directory (P1-O01).
#
#   restore.sh <backup set directory> <new database name> <release directory>
#
# Refuses to touch an existing database or a non-empty release directory, so it cannot overwrite live data. To
# recover a lost server, run it against the new PostgreSQL server under the production database name, then start the
# app (docs/operations/backup-and-restore.md). The restore drill (restore-drill.sh) runs it against scratch names.
# Needs createdb, pg_restore, psql, tar, sha256sum, and the libpq variables (PGHOST, PGUSER, PGPASSWORD).
set -euo pipefail

die() { echo "restore: $*" >&2; exit 1; }

[ "$#" -eq 3 ] || die "usage: restore.sh <backup set directory> <new database name> <release directory>"
set_dir="$1" db="$2" releases_dir="$3"
[ -d "$set_dir" ] || die "$set_dir is not a directory"
[[ "$db" =~ ^[a-z][a-z0-9_]{0,62}$ ]] || die "the database name must be lowercase letters, digits, and underscores"
if [ -d "$releases_dir" ] && [ -n "$(ls -A "$releases_dir")" ]; then die "$releases_dir is not empty"; fi

(cd "$set_dir" && sha256sum --check --quiet SHA256SUMS) || die "checksum mismatch: this backup set is damaged"
if psql --no-psqlrc -X -At -d postgres -c "SELECT 1 FROM pg_database WHERE datname = '$db'" | grep -q 1; then
  die "database $db already exists"
fi

# The restore creates the database, so the role needs CREATEDB (or to be a superuser). A PostgreSQL that was set up
# with the role owning ready-made databases may not have given it: say what to run, rather than createdb's error.
role="$(psql --no-psqlrc -X -At -d postgres -c "SELECT current_user || ' ' || (rolcreatedb OR rolsuper)::text FROM pg_roles WHERE rolname = current_user")"
if [ "${role##* }" != true ]; then
  die "the PostgreSQL role ${role% *} may not create databases, which a restore and the restore drill need. Run this once as a PostgreSQL superuser: ALTER ROLE ${role% *} CREATEDB;"
fi
createdb "$db"
if ! pg_restore --no-owner --no-privileges --exit-on-error --dbname "$db" "$set_dir/fleet-cmdb.dump"; then
  dropdb --if-exists "$db"
  die "pg_restore failed; $db was dropped"
fi
mkdir -p "$releases_dir"
tar -C "$releases_dir" -xf "$set_dir/releases.tar"
echo "restore: database $db and release files in $releases_dir restored from $set_dir"
