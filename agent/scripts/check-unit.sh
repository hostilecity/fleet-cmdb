#!/bin/sh
# Checks the agent's systemd unit with systemd-analyze (P1-PACKAGING), as CI does:
#
#   scripts/check-unit.sh [UNIT]      (default: src/install/fleet-agent.service, run from agent/)
#
# 1. `systemd-analyze verify` must print nothing: an unknown or misspelt option, or a value systemd
#    cannot parse, is only a warning to systemd, so any output fails the check.
# 2. `systemd-analyze security` prints the exposure table and fails above MAX_EXPOSURE (on its 0-100
#    scale; 20 is an overall exposure of 2.0), so weakening the sandbox fails CI.
#
# The ExecStart= binary is swapped for /bin/true, since the agent is not installed where this runs.
set -eu

unit=${1:-src/install/fleet-agent.service}
max_exposure=${MAX_EXPOSURE:-20}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed 's#^ExecStart=/usr/lib/fleet-agent/current/fleet-agent #ExecStart=/bin/true #' "$unit" \
    > "$tmp/fleet-agent.service"
if ! grep -q '^ExecStart=/bin/true run$' "$tmp/fleet-agent.service"; then
    echo "check-unit: ExecStart= is not /usr/lib/fleet-agent/current/fleet-agent run" >&2
    exit 1
fi

systemd-analyze --version | head -n 1
if ! output=$(systemd-analyze verify --man=no "$tmp/fleet-agent.service" 2>&1) || [ -n "$output" ]; then
    printf '%s\n' "$output" >&2
    echo "check-unit: systemd-analyze verify reported problems with $unit" >&2
    exit 1
fi
echo "systemd-analyze verify: no problems"

systemd-analyze security --offline=yes --no-pager --threshold="$max_exposure" "$tmp/fleet-agent.service"
