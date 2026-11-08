#!/usr/bin/env bash
# Prints the server's .env for the layout with an existing PostgreSQL and a tunnel on another machine (P1-O03),
# built from environment variables. .github/workflows/deploy.yml runs it with the GitHub environment's secrets and
# variables and pipes the output over SSH into the server's .env, so no value is written to the runner's disk, put
# on a command line, or logged. ops/deploy/smoke-test.sh runs it the same way.
#
#   write-env.sh > .env           # exit status 2 and the names (never the values) of missing or invalid settings
#
# Each value is written single-quoted, so Docker Compose takes it literally ($ and # included). A value may not hold
# a single quote, a newline, or a carriage return. The last line is "# end", so the receiving side can tell a whole
# file from a cut-off one. Settings: docs/operations/configuration.md; the GitHub side: install-server.md.
set -euo pipefail

required=(
  FLEET_DASHBOARD_HOST FLEET_AGENT_HOST
  SECRET_KEY_BASE DATABASE_PASSWORD GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET CLOUDFLARE_DNS_API_TOKEN ACME_EMAIL
  FLEET_DB_NETWORK FLEET_TUNNEL_SOURCE_RANGE
)
optional=(
  FLEET_DB_HOST FLEET_RELEASE_KEY_CURRENT FLEET_RELEASE_KEY_NEXT FLEET_ADVISORY_FEED_TOKEN
  FLEET_DATA_DIR BACKUP_DIR FLEET_AGENT_BIND_ADDRESS FLEET_DASHBOARD_BIND_ADDRESS FLEET_DASHBOARD_PORT
)
# FLEET_EXTRA_SETTINGS: further non-secret settings, one NAME=value per line (blank lines and # comments skipped),
# for example FLEET_SESSION_IDLE_MINUTES=60. It may not repeat a setting above or change COMPOSE_FILE.

problems=()
valid_value() { [[ "$1" != *"'"* && "$1" != *$'\n'* && "$1" != *$'\r'* ]]; }

lines=()
emit() { # emit <name> <value>
  if valid_value "$2"; then lines+=("$1='$2'"); else problems+=("$1 holds a single quote or a line break"); fi
}

for name in "${required[@]}"; do
  if [ -n "${!name:-}" ]; then emit "$name" "${!name}"; else problems+=("$name is not set"); fi
done
for name in "${optional[@]}"; do
  if [ -n "${!name:-}" ]; then emit "$name" "${!name}"; fi
done

for name in FLEET_DASHBOARD_HOST FLEET_AGENT_HOST; do
  [[ -z "${!name:-}" || "${!name}" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || problems+=("$name is not a lowercase hostname")
done
if [ -n "${FLEET_DASHBOARD_HOST:-}" ] && [ "${FLEET_DASHBOARD_HOST}" = "${FLEET_AGENT_HOST:-}" ]; then
  problems+=("FLEET_DASHBOARD_HOST and FLEET_AGENT_HOST must differ")
fi
# Only the tunnel connector's machine: a range that admits the whole LAN would let any machine on it reach the
# dashboard without passing Cloudflare Access.
IFS=, read -r -a ranges <<< "${FLEET_TUNNEL_SOURCE_RANGE:-}"
for range in "${ranges[@]}"; do
  range="${range// /}"
  if [[ ! "$range" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] || [[ "$range" =~ /0$ ]]; then
    problems+=("FLEET_TUNNEL_SOURCE_RANGE must be addresses or CIDR ranges, comma-separated, not /0")
    break
  fi
done

managed=" COMPOSE_FILE ${required[*]} ${optional[*]} "
seen=" "
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  if [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
    name="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
    if [[ "$managed" == *" $name "* || "$name" == COMPOSE_* ]]; then
      problems+=("FLEET_EXTRA_SETTINGS sets $name, which has its own GitHub setting or is not allowed")
    elif [[ "$seen" == *" $name "* ]]; then
      problems+=("FLEET_EXTRA_SETTINGS sets $name twice")
    else
      seen+="$name "
      emit "$name" "$value"
    fi
  else
    problems+=("FLEET_EXTRA_SETTINGS has a line that is not NAME=value")
  fi
done <<< "${FLEET_EXTRA_SETTINGS:-}"

if [ "${#problems[@]}" -gt 0 ]; then
  printf 'write-env: %s\n' "${problems[@]}" >&2
  exit 2
fi

echo "# Written by .github/workflows/deploy.yml from the GitHub environment. Do not edit it on the server: the next"
echo "# deploy replaces it. Change the GitHub secret or variable and deploy again (docs/operations/install-server.md)."
echo "COMPOSE_FILE='compose.yaml'"
printf '%s\n' "${lines[@]}"
echo "# end"
