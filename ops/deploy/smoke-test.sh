#!/usr/bin/env bash
# Deployment smoke test (P1-O03), run by .github/workflows/deploy-ci.yml in each of the two layouts of
# docs/operations/install-server.md, with throwaway settings, checking what can be checked without Cloudflare:
#
#   smoke-test.sh bundled    All-in-one (compose.yaml + compose.bundled.yaml), following the guide's steps:
#     - the configuration validates, the images pull, and the app image builds;
#     - `docker compose up` brings up the database, the app (db:prepare on start), and Traefik, all healthy;
#     - through Traefik on port 443, the agent hostname serves /api/v1 and /health and nothing else;
#     - from the tunnel network (where cloudflared sits), the dashboard hostname serves the dashboard and never
#       /api/v1, even with a forged X-Forwarded-Host;
#     - /health is unhealthy until the first backup, then healthy;
#     - ops/backup/backup.sh backs up the stack, the restore drill passes, and a rebuild from that backup by the
#       documented restore procedure brings the host and audit entries back.
#
#   smoke-test.sh external   An existing PostgreSQL container and a tunnel on another machine (compose.yaml only),
#     the way .github/workflows/deploy.yml deploys, without the SSH:
#     - a PostgreSQL 17 container on its own Docker network, with the role cmdb owning the four databases and no
#       CREATEDB, stands in for the owner's PostgreSQL Compose project;
#     - ops/deploy/write-env.sh writes .env from environment variables, and ops/deploy/deploy.sh deploys (it checks
#       the network, builds, starts, and checks /up and /health);
#     - the agent hostname checks above;
#     - backup.sh runs pg_dump in a container on the database network; the restore drill fails with a clear message
#       while the role lacks CREATEDB, and passes once it has it.
#
#   Both layouts: Traefik's dashboard entrypoint (:8443) serves the dashboard hostname to the tunnel connector's
#   address only (403 for any other), never /api/v1, ignores a forged X-Forwarded-Host or Forwarded header, and does
#   not route the agent hostname.
#
# Not covered (needs real Cloudflare and Let's Encrypt): the tunnel, Access, and a trusted certificate. Traefik's ACME
# request fails with the dummy token and it serves its default certificate, so curl uses -k here, and only here.
#
# It creates and deletes a Compose project "fleet-cmdb-smoke", its Docker networks and containers, and a temporary
# data directory. Needs root (the data directories belong to other users), Docker with Compose, curl, openssl, and
# for the bundled layout PostgreSQL 17 client tools (pg_dump) on PATH.
set -euo pipefail

[ "${DEPLOY_SMOKE_DISPOSABLE:-}" = yes ] || { echo "smoke: set DEPLOY_SMOKE_DISPOSABLE=yes (CI only)" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "smoke: run as root" >&2; exit 2; }
layout="${1:-}"
case "$layout" in bundled | external) ;; *) echo "usage: smoke-test.sh bundled|external" >&2; exit 2 ;; esac

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
work="$(mktemp -d)"
data="$work/data"
backups="$work/backups"
dashboard=fleet.example.com
agent=agent.fleet.example.com
db_password="$(openssl rand -hex 24)"
project=fleet-cmdb-smoke
export COMPOSE_PROJECT_NAME="$project"
db_network="$project-database"
db_port=55432
# Addresses on the agent-proxy network (FLEET_PROXY_SUBNET's default, 172.30.47.0/28) for the dashboard checks: the
# first stands in for the tunnel connector's machine, the second for any other machine on the LAN.
tunnel_ip=172.30.47.14
other_ip=172.30.47.13
pg_container="$project-postgres"

if [ "$layout" = bundled ]; then
  env_file="$work/.env"
  cat > "$env_file" <<EOF
COMPOSE_FILE=compose.yaml:compose.bundled.yaml
FLEET_DASHBOARD_HOST=$dashboard
FLEET_AGENT_HOST=$agent
SECRET_KEY_BASE=$(openssl rand -hex 64)
CMDB_DATABASE_PASSWORD=$db_password
GOOGLE_CLIENT_ID=smoke.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=smoke-not-a-secret
CLOUDFLARE_DNS_API_TOKEN=smoke-not-a-token
CLOUDFLARE_TUNNEL_TOKEN=smoke-not-a-token
ACME_EMAIL=admin@example.com
ACME_CA_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory
FLEET_DATA_DIR=$data
BACKUP_DIR=$backups
FLEET_DB_PORT=$db_port
FLEET_DB_NETWORK=$db_network
FLEET_AGENT_BIND_ADDRESS=127.0.0.1
FLEET_TUNNEL_SOURCE_RANGE=$tunnel_ip/32
FLEET_DASHBOARD_BIND_ADDRESS=127.0.0.1
EOF
else
  # deploy.sh uses the .env next to compose.yaml, as on the server.
  env_file="$repo/.env"
fi

compose() { docker compose -p "$project" --env-file "$env_file" "$@"; }

failed=0
cleanup() {
  status=$?
  if [ "$status" -ne 0 ] || [ "$failed" -ne 0 ]; then
    echo "::group::container logs"
    compose logs --no-color --tail 200 || true
    echo "::endgroup::"
  fi
  compose --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f "$pg_container" >/dev/null 2>&1 || true
  docker network rm "$db_network" >/dev/null 2>&1 || true
  if [ "$layout" = external ]; then rm -f "$repo/.env"; rm -rf "$repo/.deploy"; fi
  rm -rf "$work"
}
trap cleanup EXIT

step() { echo; echo "== $*"; }
pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; failed=1; }
expect() { # expect <description> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: expected '$2', got '$3'"; fi
}
contains() { # contains <description> <needle> <haystack>
  if [[ "$3" == *"$2"* ]]; then pass "$1"; else fail "$1: '$2' not in '$3'"; fi
}

# Through Traefik on 127.0.0.1:443, as a VM on the LAN would reach it.
via_agent_proxy() { curl -sk --resolve "$agent:443:127.0.0.1" --resolve "$dashboard:443:127.0.0.1" "$@"; }
# From the tunnel network, as the bundled cloudflared reaches the app (the app image has curl).
via_tunnel() { docker run --rm --network "${project}_tunnel" --entrypoint curl fleet-cmdb:local -s "$@"; }
# To Traefik's dashboard entrypoint from a given address, as the tunnel connector on another machine reaches it.
# The Host header carries no port, as cloudflared sends it (the public hostname).
via_dashboard_entrypoint() { # via_dashboard_entrypoint <source address> <curl arguments>
  local ip="$1"; shift
  docker run --rm --network "${project}_agent-proxy" --ip "$ip" --entrypoint curl fleet-cmdb:local -sk \
    --connect-to "$dashboard:8443:traefik:8443" --connect-to "$agent:8443:traefik:8443" "$@"
}

agent_checks() {
  step "the agent hostname serves the agent API and health only (install step 9)"
  body="$(via_agent_proxy -X POST -H 'content-type: application/json' -d '{}' "https://$agent/api/v1")"
  contains "POST /api/v1 on the agent hostname answers the API's not_found" '"code":"not_found"' "$body"
  body="$(via_agent_proxy -X POST -w ' %{http_code}' "https://$agent/api/v1/heartbeat")"
  contains "an unauthenticated heartbeat on the agent hostname is 401" '"code":"unauthorized"' "$body"
  expect "the dashboard on the agent hostname is 404" 404 "$(via_agent_proxy -o /dev/null -w '%{http_code}' "https://$agent/")"
  expect "the dashboard hostname is not routed by Traefik on 443" 404 "$(via_agent_proxy -o /dev/null -w '%{http_code}' "https://$dashboard/sign_in")"
  expect "a forged X-Forwarded-Host through Traefik does not reach the dashboard" 404 \
    "$(via_agent_proxy -o /dev/null -w '%{http_code}' -H "X-Forwarded-Host: $dashboard" "https://$agent/sign_in")"
  expect "a forged Forwarded host through Traefik does not reach the dashboard" 404 \
    "$(via_agent_proxy -o /dev/null -w '%{http_code}' -H "Forwarded: host=$dashboard" "https://$agent/sign_in")"
}

dashboard_entrypoint_checks() {
  step "Traefik's dashboard entrypoint serves the tunnel connector's address only, and never the agent API"
  local url="https://$dashboard:8443"
  expect "the sign-in page renders for the tunnel connector" 200 \
    "$(via_dashboard_entrypoint "$tunnel_ip" -o /dev/null -w '%{http_code}' -H "Host: $dashboard" "$url/sign_in")"
  expect "the dashboard redirects to sign-in on the public URL, without the entrypoint's port" "302 https://$dashboard/sign_in" \
    "$(via_dashboard_entrypoint "$tunnel_ip" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $dashboard" "$url/")"
  expect "a forged Forwarded host is removed (the redirect stays on the dashboard hostname)" "302 https://$dashboard/sign_in" \
    "$(via_dashboard_entrypoint "$tunnel_ip" -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $dashboard" \
      -H "Forwarded: host=$agent;proto=https" "$url/")"
  expect "POST /api/v1/heartbeat on the dashboard hostname is 404" 404 \
    "$(via_dashboard_entrypoint "$tunnel_ip" -o /dev/null -w '%{http_code}' -X POST -H "Host: $dashboard" "$url/api/v1/heartbeat")"
  expect "a forged X-Forwarded-Host for the agent hostname is replaced" 404 \
    "$(via_dashboard_entrypoint "$tunnel_ip" -o /dev/null -w '%{http_code}' -X POST -H "Host: $dashboard" \
      -H "X-Forwarded-Host: $agent" "$url/api/v1/heartbeat")"
  expect "/health on the dashboard hostname is 404" 404 \
    "$(via_dashboard_entrypoint "$tunnel_ip" -o /dev/null -w '%{http_code}' -H "Host: $dashboard" "$url/health")"
  expect "the agent hostname is not routed on the dashboard entrypoint" 404 \
    "$(via_dashboard_entrypoint "$tunnel_ip" -o /dev/null -w '%{http_code}' -X POST "https://$agent:8443/api/v1/heartbeat")"
  expect "another address gets 403" 403 \
    "$(via_dashboard_entrypoint "$other_ip" -o /dev/null -w '%{http_code}' -H "Host: $dashboard" "$url/sign_in")"
}

health_before_backup() {
  step "/health is unhealthy before the first backup"
  body="$(via_agent_proxy -w ' %{http_code}' "https://$agent/health")"
  contains "/health is 503" ' 503' "$body"
  contains "the backup check fails" '"backup":"failing"' "$body"
}

health_after_backup() {
  step "/health turns healthy once backed up and the jobs have run (install step 12)"
  healthy=""
  for _ in $(seq 1 60); do
    body="$(via_agent_proxy "https://$agent/health")"
    if [[ "$body" == *'"status":"ok"'* ]]; then healthy=yes; break; fi
    sleep 3
  done
  if [ -n "$healthy" ]; then pass "/health is ok: $body"; else fail "/health never became ok: $body"; fi
}

operator_and_host() {
  step "first operator and a pre-registered host (install step 10, install-agent.md)"
  compose exec -T app bin/rails operators:allow EMAIL=operator@example.com
  compose exec -T app bin/rails operators:list
  compose exec -T app bin/rails hosts:create DISPLAY_NAME="Smoke test" VM_HOSTNAME=vm-01.example.lan TAGS=lab >/dev/null
  pass "operator and host created"
}

newest_set() { find "$backups" -maxdepth 1 -type d -name 'fleet-cmdb-*' | sort | tail -n 1; }

acme_check() {
  step "certificate renewal failure is visible in the Traefik log"
  acme_errors="$(compose logs --no-color traefik | grep -iE '(ERR|error).*acme|acme.*(ERR|error)' || true)"
  if [ -n "$acme_errors" ]; then
    pass "Traefik logs the failed certificate request (dummy token):"
    printf '%s\n' "$acme_errors" | head -n 3
  else
    fail "no ACME error in the Traefik log"
  fi
}

bundled() {
  step "configuration validates (install step 7)"
  compose config --quiet
  pass "docker compose config"

  step "images pull and build (install step 8)"
  compose pull --quiet db traefik cloudflared
  compose build --quiet app
  pass "images"

  step "data directories and start (install step 8)"
  install -d -m 0755 "$data"
  install -d -m 0750 -o 1000 -g 1000 "$data/releases"
  install -d -m 0755 "$data/backup"
  install -d -m 0700 "$data/certs"
  install -d -m 0700 "$backups"
  compose up -d --wait --wait-timeout 300 db app traefik
  compose ps

  agent_checks

  step "the dashboard hostname never serves the agent API, from the tunnel network"
  expect "POST /api/v1/heartbeat on the dashboard hostname is 404" 404 \
    "$(via_tunnel -o /dev/null -w '%{http_code}' -X POST -H "Host: $dashboard" http://app:3000/api/v1/heartbeat)"
  expect "a forged X-Forwarded-Host from the tunnel is ignored" 404 \
    "$(via_tunnel -o /dev/null -w '%{http_code}' -X POST -H "Host: $dashboard" -H "X-Forwarded-Host: $agent" http://app:3000/api/v1/heartbeat)"
  expect "/health on the dashboard hostname is 404" 404 "$(via_tunnel -o /dev/null -w '%{http_code}' -H "Host: $dashboard" http://app:3000/health)"
  expect "the dashboard redirects to sign-in" "302 https://$dashboard/sign_in" \
    "$(via_tunnel -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $dashboard" http://app:3000/)"
  expect "the sign-in page renders" 200 "$(via_tunnel -o /dev/null -w '%{http_code}' -H "Host: $dashboard" http://app:3000/sign_in)"

  dashboard_entrypoint_checks
  health_before_backup
  operator_and_host

  step "backup (install step 11)"
  backup_env() {
    env BACKUP_DIR="$backups" BACKUP_ALLOW_LOCAL=1 FLEET_RELEASES_DIR="$data/releases" \
      FLEET_BACKUP_STATUS_FILE="$data/backup/last_success" PGHOST=127.0.0.1 PGPORT="$db_port" PGUSER=cmdb \
      PGPASSWORD="$db_password" "$@"
  }
  backup_env ops/backup/backup.sh
  set_dir="$(newest_set)"
  if [ -n "$set_dir" ]; then pass "backup set $(basename "$set_dir")"; else fail "no backup set written"; exit 1; fi

  health_after_backup

  step "restore drill (backup-and-restore.md)"
  compose --profile tools run --rm restore-drill

  step "rebuild from the backup (backup-and-restore.md, Restore)"
  compose down
  mv "$data/postgres" "$data/postgres.lost"
  rm -rf "$data/releases"
  install -d -m 0750 -o 1000 -g 1000 "$data/releases"
  compose up -d --wait db
  backup_env ops/backup/restore.sh "$set_dir" cmdb_production "$data/releases"
  chown -R 1000:1000 "$data/releases"
  compose up -d --wait --wait-timeout 300 db app traefik
  # One "name=value" line per count; the app's JSON log lines on the same output are skipped.
  counts="$(compose exec -T app bin/rails runner '
    puts "hosts=#{Host.where(hostname: "vm-01.example.lan").count}"
    puts "operators=#{OperatorAllowlistEntry.where(email: "operator@example.com").count}"
    puts "audit=#{AuditEntry.count}"')"
  count() { printf '%s\n' "$counts" | sed -n "s/^$1=\([0-9][0-9]*\)$/\1/p"; }
  expect "the restored database has the host" 1 "$(count hosts)"
  expect "the restored database has the operator" 1 "$(count operators)"
  audit="$(count audit)"
  if [ "${audit:-0}" -ge 2 ]; then pass "the restored database has $audit audit entries"; else fail "audit entries after restore: '$audit'"; fi
  body="$(via_agent_proxy -X POST -H 'content-type: application/json' -d '{}' "https://$agent/api/v1")"
  contains "the rebuilt stack answers on the agent hostname" '"code":"not_found"' "$body"

  acme_check
}

external() {
  step "an existing PostgreSQL container on its own network, as a separate Compose project would run it"
  docker network create "$db_network" >/dev/null
  docker run -d --name "$pg_container" --network "$db_network" --network-alias postgres \
    -e POSTGRES_PASSWORD="$(openssl rand -hex 24)" postgres:17 >/dev/null
  for _ in $(seq 1 60); do
    if docker exec "$pg_container" pg_isready -q -U postgres; then break; fi
    sleep 1
  done
  # The role owns the four databases and may not create databases, as on the owner's server. The password goes in
  # on standard input.
  docker exec -i "$pg_container" psql -q -v ON_ERROR_STOP=1 -U postgres <<SQL
CREATE ROLE cmdb LOGIN PASSWORD '$db_password';
CREATE DATABASE cmdb_production OWNER cmdb;
CREATE DATABASE cmdb_production_cache OWNER cmdb;
CREATE DATABASE cmdb_production_queue OWNER cmdb;
CREATE DATABASE cmdb_production_cable OWNER cmdb;
SQL
  pass "PostgreSQL on $db_network with the role cmdb (no CREATEDB) and its four databases"

  step "the deploy refuses a database network that does not exist"
  install -d -m 0700 "$backups"
  # A value with $ and #, which Compose would expand or cut if it were not quoted in .env.
  # shellcheck disable=SC2016
  literal_secret='smoke-not-a-secret-$HOME-#x'
  settings() {
    env FLEET_DASHBOARD_HOST="$dashboard" FLEET_AGENT_HOST="$agent" SECRET_KEY_BASE="$(openssl rand -hex 64)" \
      CMDB_DATABASE_PASSWORD="$db_password" GOOGLE_CLIENT_ID=smoke.apps.googleusercontent.com \
      GOOGLE_CLIENT_SECRET="$literal_secret" CLOUDFLARE_DNS_API_TOKEN=smoke-not-a-token \
      ACME_EMAIL=admin@example.com FLEET_DB_NETWORK="$1" FLEET_TUNNEL_SOURCE_RANGE="$tunnel_ip/32" \
      FLEET_DATA_DIR="$data" BACKUP_DIR="$backups" FLEET_AGENT_BIND_ADDRESS=127.0.0.1 \
      FLEET_DASHBOARD_BIND_ADDRESS=127.0.0.1 \
      FLEET_EXTRA_SETTINGS=$'# Let\'s Encrypt staging, for the dummy token\nACME_CA_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory\n\nFLEET_SESSION_IDLE_MINUTES=60' \
      ops/deploy/write-env.sh > "$env_file"
    chmod 600 "$env_file"
  }
  settings "$project-no-such-network"
  if out="$(ops/deploy/deploy.sh 2>&1)"; then fail "deploy.sh ran without the database network"; else
    contains "deploy.sh names the missing network" "the database network '$project-no-such-network' does not exist" "$out"
  fi
  if (FLEET_DASHBOARD_HOST=x ops/deploy/write-env.sh >/dev/null 2>"$work/write-env.err"); then
    fail "write-env.sh accepted missing settings"
  else
    contains "write-env.sh names a missing setting" "SECRET_KEY_BASE is not set" "$(cat "$work/write-env.err")"
  fi

  step "deploy (ops/deploy/deploy.sh, as .github/workflows/deploy.yml runs it on the server)"
  settings "$db_network"
  compose config --quiet
  pass "docker compose config with compose.yaml alone and the external network"
  ops/deploy/deploy.sh
  compose ps
  expect "the bundled database is not part of this layout" "" "$(compose ps --services --all | grep -x db || true)"
  expect "a secret with \$ and # reaches the app literally" "$literal_secret" \
    "$(compose exec -T app printenv GOOGLE_CLIENT_SECRET)"
  expect "an extra setting reaches the app" 60 "$(compose exec -T app printenv FLEET_SESSION_IDLE_MINUTES)"

  agent_checks
  dashboard_entrypoint_checks
  health_before_backup
  operator_and_host

  step "a second deploy of the same code (an upgrade) keeps the data"
  ops/deploy/deploy.sh >/dev/null
  expect "the operator is still there" 1 "$(compose exec -T app bin/rails runner \
    'puts "operators=#{OperatorAllowlistEntry.where(email: "operator@example.com").count}"' \
    | sed -n 's/^operators=\([0-9][0-9]*\)$/\1/p')"

  step "backup in a container on the database network (backup-and-restore.md, existing PostgreSQL)"
  env BACKUP_DIR="$backups" BACKUP_ALLOW_LOCAL=1 FLEET_RELEASES_DIR="$data/releases" \
    FLEET_BACKUP_STATUS_FILE="$data/backup/last_success" FLEET_DB_NETWORK="$db_network" PGHOST=postgres \
    PGUSER=cmdb PGPASSWORD="$db_password" ops/backup/backup.sh
  set_dir="$(newest_set)"
  if [ -n "$set_dir" ]; then pass "backup set $(basename "$set_dir")"; else fail "no backup set written"; exit 1; fi
  expect "the release directory still belongs to the app" "1000 750" "$(stat -c '%u %a' "$data/releases")"

  health_after_backup

  step "restore drill without CREATEDB fails clearly"
  if out="$(compose --profile tools run --rm restore-drill 2>&1)"; then fail "the drill passed without CREATEDB"; else
    contains "the drill says what to run" "ALTER ROLE cmdb CREATEDB;" "$out"
  fi

  step "restore drill with CREATEDB (the one-time SQL in install-server.md)"
  docker exec "$pg_container" psql -q -v ON_ERROR_STOP=1 -U postgres -c 'ALTER ROLE cmdb CREATEDB;'
  compose --profile tools run --rm restore-drill
  pass "restore drill"

  acme_check
}

"$layout"

echo
if [ "$failed" -ne 0 ]; then echo "Deployment smoke test ($layout) FAILED"; exit 1; fi
echo "Deployment smoke test ($layout) passed."
