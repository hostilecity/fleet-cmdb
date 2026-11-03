#!/usr/bin/env bash
# Deployment smoke test (P1-O03), run by .github/workflows/deploy-ci.yml. It follows docs/operations/install-server.md
# with throwaway settings and checks what can be checked without Cloudflare:
#
#   - compose.yaml validates, its images pull, and the app image builds;
#   - `docker compose up` brings up the database, the app (db:prepare on start), and Traefik, all healthy;
#   - through Traefik on port 443, the agent hostname serves /api/v1 and /health and nothing else;
#   - from the tunnel network (where cloudflared sits), the dashboard hostname serves the dashboard and never
#     /api/v1, even with a forged X-Forwarded-Host;
#   - /health is unhealthy until the first backup, then healthy;
#   - ops/backup/backup.sh backs up the stack, the restore drill passes, and a rebuild from that backup by the
#     documented restore procedure brings the host and audit entries back.
#
# Not covered (needs real Cloudflare and Let's Encrypt): the tunnel, Access, and a trusted certificate. Traefik's ACME
# request fails with the dummy token and it serves its default certificate, so curl uses -k here, and only here.
#
# It creates and deletes a Compose project "fleet-cmdb-smoke" and a temporary data directory. Needs root (the data
# directories belong to other users), Docker with Compose, curl, and PostgreSQL 17 client tools (pg_dump) on PATH.
set -euo pipefail

[ "${DEPLOY_SMOKE_DISPOSABLE:-}" = yes ] || { echo "smoke: set DEPLOY_SMOKE_DISPOSABLE=yes (CI only)" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "smoke: run as root" >&2; exit 2; }

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
work="$(mktemp -d)"
data="$work/data"
backups="$work/backups"
dashboard=fleet.example.com
agent=agent.fleet.example.com
db_password="$(openssl rand -hex 24)"
project=fleet-cmdb-smoke
db_port=55432

cat > "$work/.env" <<EOF
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
FLEET_AGENT_BIND_ADDRESS=127.0.0.1
EOF

compose() { docker compose -p "$project" --env-file "$work/.env" "$@"; }

failed=0
cleanup() {
  status=$?
  if [ "$status" -ne 0 ] || [ "$failed" -ne 0 ]; then
    echo "::group::container logs"
    compose logs --no-color --tail 200 || true
    echo "::endgroup::"
  fi
  compose --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
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
# From the tunnel network, as cloudflared reaches the app (the app image has curl).
via_tunnel() { docker run --rm --network "${project}_tunnel" --entrypoint curl fleet-cmdb:local -s "$@"; }

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

step "the agent hostname serves the agent API and health only (install step 9)"
body="$(via_agent_proxy -X POST -H 'content-type: application/json' -d '{}' "https://$agent/api/v1")"
contains "POST /api/v1 on the agent hostname answers the API's not_found" '"code":"not_found"' "$body"
body="$(via_agent_proxy -X POST -w ' %{http_code}' "https://$agent/api/v1/heartbeat")"
contains "an unauthenticated heartbeat on the agent hostname is 401" '"code":"unauthorized"' "$body"
expect "the dashboard on the agent hostname is 404" 404 "$(via_agent_proxy -o /dev/null -w '%{http_code}' "https://$agent/")"
expect "the dashboard hostname is not routed by Traefik" 404 "$(via_agent_proxy -o /dev/null -w '%{http_code}' "https://$dashboard/sign_in")"
expect "a forged X-Forwarded-Host through Traefik does not reach the dashboard" 404 \
  "$(via_agent_proxy -o /dev/null -w '%{http_code}' -H "X-Forwarded-Host: $dashboard" "https://$agent/sign_in")"

step "the dashboard hostname never serves the agent API, from the tunnel network"
expect "POST /api/v1/heartbeat on the dashboard hostname is 404" 404 \
  "$(via_tunnel -o /dev/null -w '%{http_code}' -X POST -H "Host: $dashboard" http://app:3000/api/v1/heartbeat)"
expect "a forged X-Forwarded-Host from the tunnel is ignored" 404 \
  "$(via_tunnel -o /dev/null -w '%{http_code}' -X POST -H "Host: $dashboard" -H "X-Forwarded-Host: $agent" http://app:3000/api/v1/heartbeat)"
expect "/health on the dashboard hostname is 404" 404 "$(via_tunnel -o /dev/null -w '%{http_code}' -H "Host: $dashboard" http://app:3000/health)"
expect "the dashboard redirects to sign-in" "302 https://$dashboard/sign_in" \
  "$(via_tunnel -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $dashboard" http://app:3000/)"
expect "the sign-in page renders" 200 "$(via_tunnel -o /dev/null -w '%{http_code}' -H "Host: $dashboard" http://app:3000/sign_in)"

step "/health is unhealthy before the first backup"
body="$(via_agent_proxy -w ' %{http_code}' "https://$agent/health")"
contains "/health is 503" ' 503' "$body"
contains "the backup check fails" '"backup":"failing"' "$body"

step "first operator and a pre-registered host (install step 10, install-agent.md)"
compose exec -T app bin/rails operators:allow EMAIL=operator@example.com
compose exec -T app bin/rails operators:list
compose exec -T app bin/rails hosts:create DISPLAY_NAME="Smoke test" VM_HOSTNAME=vm-01.example.lan TAGS=lab >/dev/null
pass "operator and host created"

step "backup (install step 11)"
backup_env() {
  env BACKUP_DIR="$backups" BACKUP_ALLOW_LOCAL=1 FLEET_RELEASES_DIR="$data/releases" \
    FLEET_BACKUP_STATUS_FILE="$data/backup/last_success" PGHOST=127.0.0.1 PGPORT="$db_port" PGUSER=cmdb \
    PGPASSWORD="$db_password" "$@"
}
backup_env ops/backup/backup.sh
set_dir="$(find "$backups" -maxdepth 1 -type d -name 'fleet-cmdb-*' | sort | tail -n 1)"
if [ -n "$set_dir" ]; then pass "backup set $(basename "$set_dir")"; else fail "no backup set written"; exit 1; fi

step "/health turns healthy once backed up and the jobs have run (install step 12)"
healthy=""
for _ in $(seq 1 60); do
  body="$(via_agent_proxy "https://$agent/health")"
  if [[ "$body" == *'"status":"ok"'* ]]; then healthy=yes; break; fi
  sleep 3
done
if [ -n "$healthy" ]; then pass "/health is ok: $body"; else fail "/health never became ok: $body"; fi

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

step "certificate renewal failure is visible in the Traefik log"
acme_errors="$(compose logs --no-color traefik | grep -iE '(ERR|error).*acme|acme.*(ERR|error)' || true)"
if [ -n "$acme_errors" ]; then
  pass "Traefik logs the failed certificate request (dummy token):"
  printf '%s\n' "$acme_errors" | head -n 3
else
  fail "no ACME error in the Traefik log"
fi

echo
if [ "$failed" -ne 0 ]; then echo "Deployment smoke test FAILED"; exit 1; fi
echo "Deployment smoke test passed."
