#!/usr/bin/env bash
# Backups in the deployment (#138, docs/operations/backup-and-restore.md). Runs on the app's VM as the deploy user
# (in the docker group), from the copy that ops/backup/install.sh keeps in ~/.local/share/fleet-cmdb/backup:
#
#   docker.sh backup [--force]     one backup now (the user timer fleet-cmdb-backup.timer runs this daily); --force
#                                  writes it even if the database holds fewer hosts or audit entries than the
#                                  newest set (backup.sh explains why that is refused)
#   docker.sh first-backup         start the timer's backup in the background if BACKUP_DIR holds no set yet (the
#                                  deploy runs this)
#   docker.sh restore-drill [SET]  the restore drill on the newest set, or on SET (a fleet-cmdb-<UTC time> name)
#   docker.sh restore SET [--force]
#                                  recover a lost server: SET into cmdb_production (and its queue, cache, and cable
#                                  databases) and the storage volume, then a backup of the restored state; the app
#                                  must be stopped. --force accepts a set that holds no host and no audit entry
#   docker.sh list                 the backup sets, their sizes, and their counts
#   docker.sh delete SET           delete one set (not the newest), for example a set retention keeps because it holds
#                                  more than the newest set after a deliberate fresh start
#   docker.sh pull                 pull the PostgreSQL client image (install.sh does this; a failure only warns)
#
# The PostgreSQL client tools run in a throwaway container of BACKUP_PG_IMAGE (default postgres:17) on the database's
# Docker network, so the database needs no published port and the VM no PostgreSQL client. Those containers run as
# the app's uid 1000 with no capabilities and write the sets to BACKUP_DIR, which must belong to uid 1000. A backup
# mounts the app's storage volume (fleet-cmdb_storage) read-only, for the release files; the status file /health
# reads is then written by the app's own image, in a container with no network. Only a restore writes release files
# through the PostgreSQL image, into a stopped app's volume or the drill's scratch volume.
#
# Secrets are never stored for the backup: the database host and password are read at run time from the fleet-cmdb
# container's settings (docker inspect; the container may be stopped) and passed to containers by name (docker run
# -e PGPASSWORD), never on a command line. The other settings, none secret, are in ~/.config/fleet-cmdb/backup.env
# (FLEET_BACKUP_ENV overrides the path), written by the Deploy workflow: literal NAME=value lines, read, never sourced.
#
# Backup, restore, the drill, and the deploy (ops/deploy/deploy.sh) take one lock, ~/.local/state/fleet-cmdb/backup.lock:
# a backup or drill waits up to an hour for another holder, and refuses while a restore runs; a restore refuses while
# anything else runs. Settings and the app's image are read only once the lock is held, so a deploy that ran
# meanwhile is seen. A restore leaves ~/.local/state/fleet-cmdb/restore-incomplete until it succeeds (removed at once
# if it refused without changing anything); while it exists, backups, install.sh, and deploys refuse.
set -euo pipefail

ops="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
config="${FLEET_BACKUP_ENV:-$HOME/.config/fleet-cmdb/backup.env}"
lock_file="$HOME/.local/state/fleet-cmdb/backup.lock"
restore_marker="$HOME/.local/state/fleet-cmdb/restore-incomplete"
app=fleet-cmdb
volume=fleet-cmdb_storage

die() { echo "fleet-cmdb backup: $*" >&2; exit 1; }
log() { echo "fleet-cmdb backup: $*"; }

[ -r "$config" ] || die "$config is missing: the Deploy workflow writes it (docs/operations/backup-and-restore.md)"
while IFS= read -r line || [ -n "$line" ]; do
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  name="${line%%=*}"
  case "$name" in
    FLEET_DB_NETWORK | BACKUP_DIR | BACKUP_ALLOW_LOCAL | BACKUP_DB_NAME | BACKUP_RETENTION_DAYS | BACKUP_KEEP_MIN | \
      BACKUP_PG_IMAGE | BACKUP_DRILL_PGHOST)
      printf -v "$name" '%s' "${line#*=}"
      export "${name?}"
      ;;
  esac
done < "$config"
for name in FLEET_DB_NETWORK BACKUP_DIR; do
  [ -n "${!name:-}" ] || die "$name is not set in $config"
done
image="${BACKUP_PG_IMAGE:-postgres:17}"
db="${BACKUP_DB_NAME:-cmdb_production}"

wait_for_docker() { # the timer may fire just after boot (Persistent=true)
  local out=""
  for _ in $(seq 1 24); do
    if out="$(docker info 2>&1 > /dev/null)"; then return 0; fi
    if [[ "$out" == *"permission denied"* ]]; then
      die "$(id -un) may not use Docker: add it to the docker group, then restart its systemd instance (as root: systemctl restart user@$(id -u).service)"
    fi
    sleep 5
  done
  die "Docker is not running: $out"
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

# The database connection and the app's image, from the fleet-cmdb container (running or stopped).
app_settings() {
  local env_lines line
  env_lines="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$app" 2> /dev/null)" \
    || die "there is no $app container: deploy the app first (the backup reads the database settings from it)"
  PGHOST="" PGPASSWORD=""
  while IFS= read -r line; do
    case "$line" in
      PGHOST=*) PGHOST="${line#PGHOST=}" ;;
      DATABASE_PASSWORD=*) PGPASSWORD="${line#DATABASE_PASSWORD=}" ;;
    esac
  done <<< "$env_lines"
  if [ -z "$PGHOST" ] || [ -z "$PGPASSWORD" ]; then die "the $app container has no PGHOST or DATABASE_PASSWORD setting"; fi
  export PGHOST PGPASSWORD PGUSER=cmdb
  app_image="$(docker inspect -f '{{.Config.Image}}' "$app")"
}

# The lock shared with the deploy. $1: what is running; $2: seconds to wait for another holder (0: refuse at once).
# A restore is never waited for: whatever wants the lock refuses while one runs.
take_lock() {
  local holder
  mkdir -p "$(dirname "$lock_file")"
  exec 9>> "$lock_file"
  if ! flock -n 9; then
    holder="$(cat "$lock_file" 2> /dev/null || true)"
    if [ "$2" -gt 0 ] && [[ "$holder" != restore* ]]; then
      log "waiting for: $holder"
      flock -w "$2" 9 || die "still busy after $2 seconds: $holder ($lock_file)"
    else
      die "refused: busy with $holder ($lock_file)"
    fi
  fi
  printf '%s since %s, pid %s\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" > "$lock_file"
}

# A restore that did not finish leaves the databases and the volume in an unknown state.
check_restore_marker() {
  [ ! -e "$restore_marker" ] || die "refused: $(cat "$restore_marker"). Run docker.sh restore again (drop the databases its message named first). If you are sure the databases are fine, delete $restore_marker"
}

# docker run of the PostgreSQL client image on the database network, as uid 1000 with no capabilities, with the
# libpq variables passed by name. --init, so a docker stop or the unit's timeout reaches the script. Arguments:
# further docker run options, the image, and the command.
pg_run() {
  docker run --rm --init --network "$FLEET_DB_NETWORK" --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
    -e HOME=/tmp -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD -v "$ops:/ops:ro" "$@"
}

# A new Docker volume belongs to root; give its top directory to uid 1000 (a container with only CAP_CHOWN).
own_volume() {
  docker run --rm --network none --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges -v "$1:/v" \
    --entrypoint chown "$image" 1000:1000 /v
}

# The newest set's name in BACKUP_DIR, or nothing (listed in a container: the sets belong to uid 1000, mode 0700).
newest_set() {
  pg_run -v "$BACKUP_DIR:/backups:ro" --entrypoint sh "$image" -c \
    'ls -1d /backups/fleet-cmdb-* 2> /dev/null | sort | tail -n 1 | xargs -r basename'
}

# The set's directory name: the one given, or the newest.
resolve_set() {
  local name="${1:-}"
  if [ -z "$name" ]; then
    name="$(newest_set)"
    [ -n "$name" ] || die "no backup set in $BACKUP_DIR"
  fi
  name="$(basename "$name")"
  [[ "$name" =~ ^fleet-cmdb-[0-9]{8}T[0-9]{6}Z$ ]] || die "$name is not a backup set name (fleet-cmdb-<UTC time>)"
  printf '%s' "$name"
}

set_counts() { pg_run -v "$BACKUP_DIR:/backups:ro" --entrypoint cat "$image" "/backups/$1/counts"; }

# A set that holds no host and no audit entry is the backup of an empty server.
looks_empty() { [[ "$1" == *"hosts=0"* && "$1" == *"audit_entries=0"* ]]; }

do_backup() { # $1: 1 to force
  check_backup_dir
  docker volume inspect "$volume" > /dev/null 2>&1 || die "the volume $volume does not exist: deploy the app first"
  log "backing up with $image on the Docker network $FLEET_DB_NETWORK"
  # BACKUP_DIR was checked above, on the VM; inside the container every bind mount is a mount point. The storage
  # volume is read-only there: the status file is written below, by the app's image.
  pg_run --name fleet-cmdb-backup -v "$BACKUP_DIR:/backups" -v "$volume:/storage:ro" \
    -e BACKUP_DIR=/backups -e BACKUP_ALLOW_LOCAL=1 -e FLEET_RELEASES_DIR=/storage/releases -e BACKUP_NO_STATUS=1 \
    -e BACKUP_DB_NAME="$db" -e BACKUP_FORCE="$1" -e BACKUP_RETENTION_DAYS -e BACKUP_KEEP_MIN \
    --entrypoint bash "$image" /ops/backup.sh
  # The status file /health reads: only now, after the set is complete. The directory and file hold no data.
  docker run --rm --network none --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
    -v "$volume:/rails/storage" --entrypoint sh "$app_image" \
    -c 'mkdir -p storage/backup && chmod 0755 storage/backup && touch storage/backup/last_success && chmod 0644 storage/backup/last_success'
  log "status file updated"
}

cmd_backup() {
  local force=0
  case "${1:-}" in --force) force=1 ;; "") ;; *) die "usage: docker.sh backup [--force]" ;; esac
  wait_for_docker
  check_network
  take_lock backup 3600
  check_restore_marker
  app_settings
  do_backup "$force"
}

cmd_first_backup() {
  wait_for_docker
  check_backup_dir
  local newest
  newest="$(newest_set)"
  if [ -n "$newest" ]; then
    log "$BACKUP_DIR already holds sets (the newest is $newest): no first backup; the timer takes the next one"
    return 0
  fi
  export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  systemctl --user start --no-block fleet-cmdb-backup.service
  log "no set yet: the first backup started in the background (journalctl --user -u fleet-cmdb-backup.service)"
}

cmd_restore_drill() {
  wait_for_docker
  check_network
  [ -d "$BACKUP_DIR" ] || die "$BACKUP_DIR does not exist"
  take_lock drill 3600
  app_settings
  local set counts stamp live_size target_host="${BACKUP_DRILL_PGHOST:-}"
  set="$(resolve_set "${1:-}")"
  counts="$(set_counts "$set")" || die "$set has no counts file"
  log "restore drill: set $set: $(printf '%s' "$counts" | tr '\n' ' ')"
  if [ -z "${1:-}" ] && looks_empty "$counts"; then
    die "the newest set, $set, holds no host and no audit entry: it is the backup of an empty server. Name the set to drill (docker.sh list), for example docker.sh restore-drill fleet-cmdb-<UTC time>"
  fi
  live_size="$(pg_run --entrypoint psql "$image" -X -At -d "$db" -c \
    "SELECT pg_size_pretty(sum(pg_database_size(datname))) FROM pg_database WHERE datname IN ('$db', '${db}_queue', '${db}_cache', '${db}_cable')")"
  log "restore drill: the scratch databases need about $live_size of free space on ${target_host:-the live PostgreSQL server ($PGHOST)}"
  stamp="$(date -u +%Y%m%d%H%M%S)"
  scratch="cmdb_restore_drill_${stamp}_$$"
  drill_volume="fleet-cmdb-drill-${stamp}-$$"
  drill_host="${target_host:-$PGHOST}"
  tmp="$(mktemp -d)"
  trap drill_cleanup EXIT

  docker volume create "$drill_volume" > /dev/null
  own_volume "$drill_volume"
  log "restore drill: restoring $set into the scratch databases $scratch (and _queue, _cache, _cable) on $drill_host"
  PGHOST="$drill_host" pg_run -v "$BACKUP_DIR:/backups:ro" -v "$drill_volume:/drill" --entrypoint bash "$image" \
    /ops/restore.sh "/backups/$set" "$scratch" /drill/releases

  # The app's own settings, read from its container into a mode-0600 file that is removed on exit. The drill's
  # settings below are left out of it so they cannot be overridden. FLEET_RESTORE_DRILL=1 swaps the live Solid Cache
  # for an in-process store. The app boots against the scratch primary only (DATABASE_URL); the drill enqueues no
  # job and opens no cable, so it writes nothing to the live queue and cable databases.
  (umask 077 && docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$app" \
    | grep -v -E '^(DATABASE_URL|FLEET_RELEASES_DIR|FLEET_RESTORE_DRILL|COUNTS|SOLID_QUEUE_IN_PUMA)=' > "$tmp/app.env")
  log "restore drill: booting $app_image against the scratch primary"
  docker run --rm --init --network "$FLEET_DB_NETWORK" --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
    --env-file "$tmp/app.env" -e FLEET_RESTORE_DRILL=1 -e DATABASE_URL="postgresql://$drill_host/$scratch" \
    -e FLEET_RELEASES_DIR=/drill/releases -e COUNTS="/backups/$set/counts" \
    -v "$BACKUP_DIR:/backups:ro" -v "$drill_volume:/drill:ro" --entrypoint /rails/bin/rails "$app_image" backup:verify_restore
}

drill_cleanup() {
  rm -rf "$tmp"
  # shellcheck disable=SC2016 # expanded by the container's shell
  PGHOST="$drill_host" pg_run -e PGOPTIONS='-c client_min_messages=warning' --entrypoint sh "$image" \
    -c 'for name do dropdb --if-exists "$name" || exit 1; done' sh \
    "$scratch" "${scratch}_queue" "${scratch}_cache" "${scratch}_cable" \
    || echo "fleet-cmdb backup: could not drop the scratch databases $scratch*; drop them by hand" >&2
  docker volume rm "$drill_volume" > /dev/null 2>&1 || true
}

cmd_restore() {
  local set counts force=0
  [ -n "${1:-}" ] || die "usage: docker.sh restore fleet-cmdb-<UTC time> [--force] (docker.sh list shows the sets)"
  case "${2:-}" in --force) force=1 ;; "") ;; *) die "usage: docker.sh restore fleet-cmdb-<UTC time> [--force]" ;; esac
  wait_for_docker
  check_network
  check_backup_dir
  for name in fleet-cmdb-jobs "$app"; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2> /dev/null || true)" = true ]; then
      die "the $name container is running: stop the app first (docker stop fleet-cmdb-jobs fleet-cmdb)"
    fi
  done
  take_lock "restore of $1" 0
  app_settings
  set="$(resolve_set "$1")"
  counts="$(set_counts "$set")" || die "$set has no counts file"
  log "restoring $set: $(printf '%s' "$counts" | tr '\n' ' ')"
  if looks_empty "$counts" && [ "$force" != 1 ]; then
    die "$set holds no host and no audit entry: it is the backup of an empty server. Pick an older set (docker.sh list), or add --force"
  fi
  docker volume create "$volume" > /dev/null
  own_volume "$volume"
  log "restoring $set into $db (and _queue, _cache, _cable) and the volume $volume"
  mkdir -p "$(dirname "$restore_marker")"
  printf 'a restore of %s did not finish (started %s)' "$set" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$restore_marker"
  local rc=0
  pg_run -v "$BACKUP_DIR:/backups:ro" -v "$volume:/storage" --entrypoint bash "$image" \
    /ops/restore.sh "/backups/$set" "$db" /storage/releases || rc=$?
  case "$rc" in
    0) rm -f "$restore_marker" ;;
    3) rm -f "$restore_marker"; die "the restore refused before changing anything (above)" ;;
    *) die "the restore failed part-way (above). $restore_marker stays, so backups and deploys refuse until a restore succeeds" ;;
  esac
  # A backup of the restored state at once, still under the lock: it becomes the newest set, so later backups
  # compare against it, and /health turns healthy. Forced, since an older set may have been restored on purpose.
  log "restored. Backing up the restored state"
  do_backup 1
  log "done. Start the app: docker start fleet-cmdb (and fleet-cmdb-jobs), or run Actions > Deploy"
}

cmd_list() {
  # shellcheck disable=SC2016 # expanded by the container's shell
  pg_run -v "$BACKUP_DIR:/backups:ro" --entrypoint sh "$image" -c \
    'cd /backups && for set in fleet-cmdb-*; do [ -d "$set" ] || continue; printf "%s  %s  %s\n" "$set" "$(du -sh "$set" | cut -f1)" "$(tr "\n" " " < "$set/counts" 2> /dev/null)"; done; true'
}

cmd_delete() {
  local set newest
  [ -n "${1:-}" ] || die "usage: docker.sh delete fleet-cmdb-<UTC time> (docker.sh list shows the sets)"
  wait_for_docker
  take_lock "delete of $1" 0
  set="$(resolve_set "$1")"
  newest="$(newest_set)"
  [ "$set" != "$newest" ] || die "$set is the newest set, which later backups compare against: not deleted"
  pg_run -v "$BACKUP_DIR:/backups" --entrypoint rm "$image" -rf "/backups/$set"
  log "deleted $set"
}

cmd_pull() {
  if docker pull -q "$image" > /dev/null; then
    log "pulled $image"
  elif docker image inspect "$image" > /dev/null 2>&1; then
    echo "fleet-cmdb backup: warning: could not pull $image; the copy already on this VM is used" >&2
  else
    echo "fleet-cmdb backup: warning: could not pull $image, and it is not on this VM: backups fail until it can be pulled" >&2
  fi
}

command="${1:-}"
[ "$#" -gt 0 ] && shift
case "$command" in
  backup) cmd_backup "$@" ;;
  first-backup) cmd_first_backup ;;
  restore-drill) cmd_restore_drill "${1:-}" ;;
  restore) cmd_restore "${1:-}" "${2:-}" ;;
  list) cmd_list ;;
  delete) cmd_delete "${1:-}" ;;
  pull) cmd_pull ;;
  *) die "usage: docker.sh backup [--force] | first-backup | restore-drill [SET] | restore SET [--force] | list | delete SET | pull" ;;
esac
