#!/usr/bin/env bash
# Deploys or upgrades the server stack in this checkout (P1-O03). Runs on the server, as a user in the docker group,
# from the directory holding compose.yaml and .env. .github/workflows/deploy.yml runs it over SSH after shipping the
# code and writing .env; ops/deploy/smoke-test.sh runs it in Deploy CI. Steps:
#
#   1. checks .env (present, not readable by others) and, unless the layout is all-in-one, that the existing
#      PostgreSQL container's Docker network (FLEET_DB_NETWORK) exists;
#   2. validates the configuration, builds the app image (pulling a fresh base image), and pulls the other images;
#   3. creates the persistent directories under FLEET_DATA_DIR with the owners the containers need;
#   4. starts the stack (`up -d --build --remove-orphans --wait`), recreating Traefik when its routing changed;
#   5. checks /up inside the app container, then /health on the agent hostname through Traefik from this machine.
#      A 503 is reported but does not fail the deploy: /health is unhealthy until the first backup;
#   6. prints the status and removes dangling images.
#
# No value from .env is printed.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
exec </dev/null

die() { echo "deploy: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

[ -f .env ] || die ".env is missing in $(pwd)"
case "$(stat -c %a .env)" in
  600 | 400) ;;
  *) die ".env must be readable by its owner only (chmod 600 .env): it holds every secret" ;;
esac

# The value of a setting in .env, without the quotes write-env.sh adds; empty when unset.
env_value() {
  sed -n "s/^$1=//p" .env | tail -n 1 | sed "s/^'\(.*\)'\$/\1/; s/^\"\(.*\)\"\$/\1/"
}

compose_file="$(env_value COMPOSE_FILE)"
data_dir="$(env_value FLEET_DATA_DIR)"
data_dir="${data_dir:-/var/lib/fleet-cmdb}"
agent_host="$(env_value FLEET_AGENT_HOST)"
dashboard_host="$(env_value FLEET_DASHBOARD_HOST)"
if [ -z "$agent_host" ] || [ -z "$dashboard_host" ]; then die "FLEET_AGENT_HOST and FLEET_DASHBOARD_HOST must be set in .env"; fi
# Where this machine reaches its own published ports.
local_address() { if [ -z "$1" ] || [ "$1" = 0.0.0.0 ]; then echo 127.0.0.1; else echo "$1"; fi; }
agent_address="$(local_address "$(env_value FLEET_AGENT_BIND_ADDRESS)")"
dashboard_address="$(local_address "$(env_value FLEET_DASHBOARD_BIND_ADDRESS)")"
dashboard_port="$(env_value FLEET_DASHBOARD_PORT)"
dashboard_port="${dashboard_port:-8443}"
# A staging certificate is not trusted by design; only then are the checks below made without verifying it.
insecure=()
if [[ "$(env_value ACME_CA_SERVER)" == *staging* ]]; then insecure=(-k); fi

step "checks"
docker compose version >/dev/null || die "Docker Compose is not available to $(id -un)"
if [[ "$compose_file" == *compose.bundled.yaml* ]]; then
  echo "all-in-one layout: the database and the tunnel connector run here"
else
  db_network="$(env_value FLEET_DB_NETWORK)"
  db_network="${db_network:-fleet-cmdb-database}"
  docker network inspect "$db_network" >/dev/null 2>&1 \
    || die "the database network '$db_network' does not exist. Start the PostgreSQL Compose project first, or set FLEET_DB_NETWORK to its network (docker network ls)"
  echo "database network $db_network exists"
fi
docker compose config --quiet
echo "configuration is complete"

step "images"
docker compose build --pull app
docker compose pull --quiet --ignore-buildable

step "data directories under $data_dir"
# Created through a container, as root, so the deploy user needs no sudo. The app runs as uid 1000.
docker run --rm --user 0:0 --entrypoint /bin/sh -v "$data_dir:/data" fleet-cmdb:local -c '
  install -d -m 0755 /data &&
  install -d -m 0750 -o 1000 -g 1000 /data/releases &&
  install -d -m 0755 /data/backup &&
  install -d -m 0700 /data/certs'
echo "releases/ backup/ certs/ ready"

step "start"
# Traefik reads its routing only at start, and a replaced dynamic.yml is not seen by a running container.
state=.deploy
mkdir -p "$state"
recreate_traefik=""
if ! cmp -s ops/deploy/traefik/dynamic.yml "$state/traefik-dynamic.yml"; then recreate_traefik=yes; fi
docker compose up -d --build --remove-orphans --wait --wait-timeout 300
if [ -n "$recreate_traefik" ]; then
  docker compose up -d --no-deps --force-recreate --wait --wait-timeout 120 traefik
  cp ops/deploy/traefik/dynamic.yml "$state/traefik-dynamic.yml"
fi

step "health"
docker compose exec -T app curl -fsS -o /dev/null http://localhost:3000/up || die "the app does not answer /up"
echo "app: /up answers 200"

# Through Traefik, as a VM reaches it. The first deploy waits for the certificate (up to about three minutes).
body="$(mktemp)"
trap 'rm -f "$body"' EXIT
code=000
for _ in $(seq 1 36); do
  code="$(curl -s "${insecure[@]}" --max-time 10 -o "$body" -w '%{http_code}' \
    --resolve "$agent_host:443:$agent_address" "https://$agent_host/health" || true)"
  case "$code" in 200 | 503) break ;; esac
  sleep 5
done
case "$code" in
  200) echo "agent hostname: /health is ok through Traefik" ;;
  503)
    echo "agent hostname: /health answers 503 through Traefik: $(cat "$body")"
    echo "  Expected until the first backup has run (docs/operations/backup-and-restore.md), and for a minute or two"
    echo "  after a start (job_liveness). Any other failing check needs a look: docs/operations/health-and-jobs.md"
    ;;
  *) die "the agent hostname did not answer through Traefik (last HTTP status $code). A certificate problem shows in: docker compose logs traefik" ;;
esac

# From this machine the dashboard entrypoint should refuse (403): only the tunnel connector's machine is allowed.
code="$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
  --resolve "$dashboard_host:$dashboard_port:$dashboard_address" "https://$dashboard_host:$dashboard_port/" || true)"
case "$code" in
  403) echo "dashboard entrypoint: refuses this machine (403), as it should: only FLEET_TUNNEL_SOURCE_RANGE is allowed" ;;
  404) echo "dashboard entrypoint: nothing routed (FLEET_TUNNEL_SOURCE_RANGE is not set)" ;;
  *) echo "dashboard entrypoint: answered $code to this machine. Expected 403 unless FLEET_TUNNEL_SOURCE_RANGE includes it" ;;
esac

step "status"
docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}'
docker image prune -f >/dev/null
echo "removed dangling images"
echo
echo "deploy: done"
