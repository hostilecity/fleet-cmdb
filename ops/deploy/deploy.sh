#!/usr/bin/env bash
# Builds and runs the server on its VM (P1-O03): the "Build and run" step of .github/workflows/cd.yml, run there over
# SSH from the shipped code, and by Deploy CI in its recovery check (#138).
#
#   deploy.sh <dir> <sha> <database network> <jobs container: true|false>
#
# <dir> holds build-<sha>/ (cmdb, docs/api, agent/trust, agent/release-keys) and the app's env file fleet-cmdb.env,
# which is deleted once the containers have started.
#
# First it takes the backup lock (~/.local/state/fleet-cmdb/backup.lock, ops/backup/docker.sh), held through the build
# until the new app is up: it refuses at once while a restore runs, and waits up to 30 minutes for a running
# backup or drill. A running pg_dump holds a share lock on every table, so the new app's migrations would otherwise
# queue behind it, and every query on those tables behind the migrations (#138). The backup timer, in turn, waits for
# the deploy.
set -euo pipefail

[ "$#" -eq 4 ] || { echo "usage: deploy.sh <dir> <sha> <database network> <jobs container: true|false>" >&2; exit 2; }
dir="$1" sha="$2" network="$3" jobs_container="$4"
cd "$dir"
echo "==> wait for any backup to finish (the backup lock)"
lock_file="$HOME/.local/state/fleet-cmdb/backup.lock"
mkdir -p "$(dirname "$lock_file")"
exec 9>> "$lock_file"
if ! flock -n 9; then
  holder="$(cat "$lock_file" 2> /dev/null || true)"
  if [[ "$holder" == restore* ]]; then
    echo "a restore is in progress ($holder): the app was not replaced. Deploy again when it has finished" >&2
    exit 1
  fi
  echo "waiting for: $holder"
  flock -w 1800 9 || { echo "still busy after 30 minutes: $holder. The app was not replaced" >&2; exit 1; }
fi
printf 'deploy of %s since %s, pid %s\n' "$sha" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" > "$lock_file"
echo "==> database network $network"
docker network inspect "$network" >/dev/null \
  || { echo "the Docker network $network does not exist: start the PostgreSQL container first, or fix FLEET_DB_NETWORK" >&2; exit 1; }
echo "==> storage volume"
docker volume create fleet-cmdb_storage >/dev/null
echo "==> build fleet-cmdb:$sha"
docker build --pull -q --build-context api="build-$sha/docs/api" --build-context trust="build-$sha/agent/trust" --build-context release-keys="build-$sha/agent/release-keys" -t "fleet-cmdb:$sha" -t fleet-cmdb:latest "build-$sha/cmdb"
echo "==> replace the container"
# The jobs container goes first, so no job of the old commit runs against the new commit's migrations. It is
# removed when FLEET_JOBS_CONTAINER is off too, which goes back to one container. Stopped first (SIGTERM, up to
# 30 s), so Solid Queue releases the jobs it claimed instead of leaving them to fail as pruned.
docker stop -t 30 fleet-cmdb-jobs >/dev/null 2>&1 || true
docker rm -f fleet-cmdb-jobs >/dev/null 2>&1 || true
docker rm -f fleet-cmdb >/dev/null 2>&1 || true
# No capabilities and no privilege gain (setuid): the app binds ports above 1024 and needs neither.
docker run -d --name fleet-cmdb -p 443:3443 --network "$network" --restart unless-stopped \
  --cap-drop ALL --security-opt no-new-privileges \
  -v fleet-cmdb_storage:/rails/storage --env-file fleet-cmdb.env "fleet-cmdb:$sha" >/dev/null
echo "==> wait for /up (the first start creates and migrates the databases)"
for _ in $(seq 1 60); do
  if docker exec fleet-cmdb curl -fsS -o /dev/null http://localhost:3000/up 2>/dev/null; then up=yes; break; fi
  sleep 5
done
if [ -z "${up:-}" ]; then docker logs --tail 100 fleet-cmdb; echo "the app did not answer /up" >&2; exit 1; fi
if [ "$jobs_container" = true ]; then
  # Started once the app has migrated the databases. No port; the same storage volume (job code writes release
  # files there); no capabilities and no privilege gain, which it never needs. Its settings are the app's
  # without the TLS certificate and key (FLEET_TLS_*): only Puma serves HTTPS, and this is the container that
  # parses downloaded feeds, uploads, and release archives. The env files are deleted below, and by the
  # clean-up step if this fails.
  echo "==> start the jobs container"
  (umask 077 && grep -v '^FLEET_TLS_' fleet-cmdb.env > fleet-cmdb-jobs.env)
  docker run -d --name fleet-cmdb-jobs --network "$network" --restart unless-stopped \
    --cap-drop ALL --security-opt no-new-privileges \
    -v fleet-cmdb_storage:/rails/storage --env-file fleet-cmdb-jobs.env "fleet-cmdb:$sha" ./bin/jobs >/dev/null
  rm -f fleet-cmdb-jobs.env
  # Up when its three workers (realtime, default, evaluation) have registered in the queue database.
  jobs_host="$(docker inspect -f '{{.Config.Hostname}}' fleet-cmdb-jobs)"
  for _ in $(seq 1 12); do
    workers="$(docker exec fleet-cmdb ./bin/rails runner 'print SolidQueue::Process.where(kind: "Worker", hostname: ARGV.first).count' "$jobs_host" 2>/dev/null || true)"
    [ "${workers:-0}" -ge 3 ] && break
    sleep 5
  done
  if [ "${workers:-0}" -lt 3 ]; then
    docker logs --tail 100 fleet-cmdb-jobs
    echo "the jobs container's workers did not start, so no background job runs: fix it, or set FLEET_JOBS_CONTAINER=false and run the workflow again" >&2
    exit 1
  fi
fi
rm -f fleet-cmdb.env
# The HTTPS listener agents and the tunnel use (inside the container; -k: this checks the listener, the deploy
# checked the certificate before shipping).
docker exec fleet-cmdb curl -fsSk -o /dev/null https://localhost:3443/up \
  || { docker logs --tail 100 fleet-cmdb; echo "the app does not answer HTTPS on 3443" >&2; exit 1; }
docker ps --filter name='^fleet-cmdb(-jobs)?$' --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
echo "/health: $(docker exec fleet-cmdb curl -s http://localhost:3000/health)"
docker images fleet-cmdb --format '{{.Tag}}' | grep -vx -e latest -e "$sha" | sed 's/^/fleet-cmdb:/' | xargs -r docker rmi >/dev/null || true
docker image prune -f >/dev/null
