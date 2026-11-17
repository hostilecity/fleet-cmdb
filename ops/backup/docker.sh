#!/usr/bin/env bash
# Backups in the deployment (#138, docs/operations/backup-and-restore.md). Runs on the app's VM as the deploy user
# (in the docker group), from the copy that ops/backup/install.sh keeps in ~/.local/share/fleet-cmdb/backup:
#
#   docker.sh backup               one backup now (the user timer fleet-cmdb-backup.timer runs this daily)
#   docker.sh restore-drill [SET]  the restore drill on the newest set, or on SET (a fleet-cmdb-<UTC time> name)
#   docker.sh restore SET          recover a lost server: SET into cmdb_production (and its queue, cache, and cable
#                                  databases) and the storage volume; the app must be stopped first
#   docker.sh list                 the backup sets and their sizes
#   docker.sh pull                 pull the PostgreSQL client image (the deploy does this)
#
# The PostgreSQL client tools run in a throwaway container of BACKUP_PG_IMAGE (default postgres:17) on the database's
# Docker network, so the database needs no published port and the VM no PostgreSQL client. The containers run as the
# app's uid 1000 with no capabilities: they read the release files and write the backup status file in the app's
# storage volume (fleet-cmdb_storage), which /health watches, and write the sets to BACKUP_DIR, which must belong to
# uid 1000. The drill boots the deployed image (the fleet-cmdb container's) with that container's settings.
#
# Settings come from ~/.config/fleet-cmdb/backup.env (FLEET_BACKUP_ENV overrides the path), mode 0600, written by
# the Deploy workflow (.github/workflows/cd.yml) like the app's own env file: literal NAME=value lines. The file is
# read, never sourced, and the database password reaches the containers only through the environment (docker run -e
# NAME), never on a command line.
set -euo pipefail

ops="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
config="${FLEET_BACKUP_ENV:-$HOME/.config/fleet-cmdb/backup.env}"
app=fleet-cmdb
volume=fleet-cmdb_storage

die() { echo "fleet-cmdb backup: $*" >&2; exit 1; }
log() { echo "fleet-cmdb backup: $*"; }

[ -r "$config" ] || die "$config is missing: the Deploy workflow writes it (docs/operations/backup-and-restore.md)"
while IFS= read -r line || [ -n "$line" ]; do
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  name="${line%%=*}"
  case "$name" in
    FLEET_DB_NETWORK | PGHOST | PGPORT | PGUSER | PGPASSWORD | BACKUP_DIR | BACKUP_ALLOW_LOCAL | BACKUP_DB_NAME | \
      BACKUP_RETENTION_DAYS | BACKUP_KEEP_MIN | BACKUP_PG_IMAGE)
      printf -v "$name" '%s' "${line#*=}"
      export "${name?}"
      ;;
  esac
done < "$config"
for name in FLEET_DB_NETWORK PGHOST PGUSER PGPASSWORD BACKUP_DIR; do
  [ -n "${!name:-}" ] || die "$name is not set in $config"
done
image="${BACKUP_PG_IMAGE:-postgres:17}"
db="${BACKUP_DB_NAME:-cmdb_production}"

wait_for_docker() { # the timer may fire just after boot (Persistent=true)
  for _ in $(seq 1 24); do docker info > /dev/null 2>&1 && return 0; sleep 5; done
  die "Docker is not running"
}

check_network() {
  docker network inspect "$FLEET_DB_NETWORK" > /dev/null 2>&1 \
    || die "the Docker network $FLEET_DB_NETWORK does not exist: start the PostgreSQL container first, or fix FLEET_DB_NETWORK"
}

check_backup_dir() {
  [ -d "$BACKUP_DIR" ] || die "$BACKUP_DIR does not exist: mount the backup location there and give it to uid 1000 (install-server.md)"
  case "${BACKUP_ALLOW_LOCAL:-}" in
    1 | true) ;;
    *) mountpoint -q "$BACKUP_DIR" || die "$BACKUP_DIR is not a mount point, so the sets would stay on this VM with the database. Mount an off-machine location there, or set the variable FLEET_BACKUP_ALLOW_LOCAL=true to accept that" ;;
  esac
}

# docker run of the PostgreSQL client image on the database network, as uid 1000 with no capabilities, with the
# libpq variables passed by name. Arguments: further docker run options, the image, and the command.
pg_run() {
  docker run --rm --network "$FLEET_DB_NETWORK" --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
    -e HOME=/tmp -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD -v "$ops:/ops:ro" "$@"
}

# A new Docker volume belongs to root; give its top directory to uid 1000 (a container with only CAP_CHOWN).
own_volume() {
  docker run --rm --network none --cap-drop ALL --cap-add CHOWN -v "$1:/v" --entrypoint chown "$image" 1000:1000 /v
}

# The set's directory name: the one given, or the newest in BACKUP_DIR (listed in a container, since the sets belong
# to uid 1000 with mode 0700).
resolve_set() {
  local name="${1:-}"
  if [ -z "$name" ]; then
    name="$(pg_run -v "$BACKUP_DIR:/backups:ro" --entrypoint sh "$image" -c 'ls -1d /backups/fleet-cmdb-* 2> /dev/null | sort | tail -n 1')"
    [ -n "$name" ] || die "no backup set in $BACKUP_DIR"
  fi
  name="$(basename "$name")"
  [[ "$name" =~ ^fleet-cmdb-[0-9]{8}T[0-9]{6}Z$ ]] || die "$name is not a backup set name (fleet-cmdb-<UTC time>)"
  printf '%s' "$name"
}

cmd_backup() {
  wait_for_docker
  check_network
  check_backup_dir
  docker volume inspect "$volume" > /dev/null 2>&1 || die "the volume $volume does not exist: deploy the app first"
  log "backing up with $image on the Docker network $FLEET_DB_NETWORK"
  # BACKUP_DIR was checked above, on the VM; inside the container every bind mount is a mount point.
  pg_run --name fleet-cmdb-backup -v "$BACKUP_DIR:/backups" -v "$volume:/storage" \
    -e BACKUP_DIR=/backups -e BACKUP_ALLOW_LOCAL=1 -e FLEET_RELEASES_DIR=/storage/releases \
    -e FLEET_BACKUP_STATUS_FILE=/storage/backup/last_success -e BACKUP_DB_NAME="$db" \
    -e BACKUP_RETENTION_DAYS -e BACKUP_KEEP_MIN --entrypoint bash "$image" /ops/backup.sh
}

cmd_restore_drill() {
  wait_for_docker
  check_network
  [ -d "$BACKUP_DIR" ] || die "$BACKUP_DIR does not exist"
  docker inspect "$app" > /dev/null 2>&1 || die "there is no $app container: the drill boots the deployed image with its settings"
  local set app_image stamp
  set="$(resolve_set "${1:-}")"
  app_image="$(docker inspect -f '{{.Config.Image}}' "$app")"
  stamp="$(date -u +%Y%m%d%H%M%S)"
  scratch="cmdb_restore_drill_${stamp}_$$"
  drill_volume="fleet-cmdb-drill-${stamp}-$$"
  tmp="$(mktemp -d)"
  trap drill_cleanup EXIT

  docker volume create "$drill_volume" > /dev/null
  own_volume "$drill_volume"
  log "restore drill: restoring $set into the scratch databases $scratch (and _queue, _cache, _cable)"
  pg_run -v "$BACKUP_DIR:/backups:ro" -v "$drill_volume:/drill" --entrypoint bash "$image" \
    /ops/restore.sh "/backups/$set" "$scratch" /drill/releases

  # The app's own settings, read from its container into a mode-0600 file that is removed on exit. The drill's
  # settings below are left out of it so they cannot be overridden. FLEET_RESTORE_DRILL=1 swaps the live Solid Cache
  # for an in-process store, so the drill writes nothing to the live databases.
  (umask 077 && docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$app" \
    | grep -v -E '^(DATABASE_URL|FLEET_RELEASES_DIR|FLEET_RESTORE_DRILL|COUNTS|SOLID_QUEUE_IN_PUMA)=' > "$tmp/app.env")
  log "restore drill: booting $app_image against them"
  docker run --rm --network "$FLEET_DB_NETWORK" --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
    --env-file "$tmp/app.env" -e FLEET_RESTORE_DRILL=1 -e DATABASE_URL="postgresql:///$scratch" \
    -e FLEET_RELEASES_DIR=/drill/releases -e COUNTS="/backups/$set/counts" \
    -v "$BACKUP_DIR:/backups:ro" -v "$drill_volume:/drill:ro" --entrypoint /rails/bin/rails "$app_image" backup:verify_restore
}

drill_cleanup() {
  rm -rf "$tmp"
  # shellcheck disable=SC2016 # expanded by the container's shell
  pg_run -e PGOPTIONS='-c client_min_messages=warning' --entrypoint sh "$image" -c 'for name do dropdb --if-exists "$name" || exit 1; done' sh \
    "$scratch" "${scratch}_queue" "${scratch}_cache" "${scratch}_cable" \
    || echo "fleet-cmdb backup: could not drop the scratch databases $scratch*; drop them by hand" >&2
  docker volume rm "$drill_volume" > /dev/null 2>&1 || true
}

cmd_restore() {
  [ -n "${1:-}" ] || die "usage: docker.sh restore fleet-cmdb-<UTC time> (docker.sh list shows the sets)"
  wait_for_docker
  check_network
  for name in fleet-cmdb-jobs "$app"; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2> /dev/null || true)" = true ]; then
      die "the $name container is running: stop the app first (docker stop fleet-cmdb-jobs fleet-cmdb)"
    fi
  done
  local set
  set="$(resolve_set "$1")"
  docker volume create "$volume" > /dev/null
  own_volume "$volume"
  log "restoring $set into $db (and _queue, _cache, _cable) and the volume $volume"
  pg_run -v "$BACKUP_DIR:/backups:ro" -v "$volume:/storage" --entrypoint bash "$image" \
    /ops/restore.sh "/backups/$set" "$db" /storage/releases
  log "restored. Start the app (docker start fleet-cmdb, or run Actions > Deploy), then take a backup: $0 backup"
}

cmd_list() {
  # shellcheck disable=SC2016 # expanded by the container's shell
  pg_run -v "$BACKUP_DIR:/backups:ro" --entrypoint sh "$image" -c 'cd /backups && for set in fleet-cmdb-*; do [ -d "$set" ] && du -sh "$set"; done; true'
}

command="${1:-}"
[ "$#" -gt 0 ] && shift
case "$command" in
  backup) cmd_backup ;;
  restore-drill) cmd_restore_drill "${1:-}" ;;
  restore) cmd_restore "${1:-}" ;;
  list) cmd_list ;;
  pull) docker pull -q "$image" > /dev/null && log "pulled $image" ;;
  *) die "usage: docker.sh backup | restore-drill [SET] | restore SET | list | pull" ;;
esac
