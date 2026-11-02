#!/bin/sh
# Checks the agent's systemd unit with systemd-analyze (P1-PACKAGING), as CI does:
#
#   scripts/check-unit.sh [UNIT [ROLLBACK_UNIT]]      (default: src/install/fleet-agent.service and the
#                                                      fleet-agent-rollback.service beside it, run from agent/)
#
# 1. `systemd-analyze verify` must print nothing for the service and the rollback unit its OnFailure=
#    starts (P1-AGENT-UPDATE), checked together: an unknown or misspelt option, a value systemd cannot
#    parse, or an OnFailure= naming a unit that is not there is only a warning to systemd, so any output
#    fails the check.
# 2. `systemd-analyze security` prints the exposure table of the service and fails above MAX_EXPOSURE (on
#    its 0-100 scale; 20 is an overall exposure of 2.0), so weakening the sandbox fails CI. The rollback
#    unit is not held to it: it has to change /usr/lib/fleet-agent and restart the service.
#
# The ExecStart= binaries are swapped for /bin/true, since the agent is not installed where this runs.
set -eu

unit=${1:-src/install/fleet-agent.service}
rollback_unit=${2:-$(dirname "$unit")/fleet-agent-rollback.service}
max_exposure=${MAX_EXPOSURE:-20}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed 's#^ExecStart=/usr/lib/fleet-agent/current/fleet-agent #ExecStart=/bin/true #' "$unit" \
    > "$tmp/fleet-agent.service"
if ! grep -q '^ExecStart=/bin/true run$' "$tmp/fleet-agent.service"; then
    echo "check-unit: ExecStart= is not /usr/lib/fleet-agent/current/fleet-agent run" >&2
    exit 1
fi

sed 's#^ExecStart=/usr/lib/fleet-agent/previous/fleet-agent #ExecStart=/bin/true #' "$rollback_unit" \
    > "$tmp/fleet-agent-rollback.service"
if ! grep -q '^ExecStart=/bin/true update-rollback --reason crash-loop$' "$tmp/fleet-agent-rollback.service"; then
    echo "check-unit: ExecStart= is not /usr/lib/fleet-agent/previous/fleet-agent update-rollback --reason crash-loop" >&2
    exit 1
fi
if ! grep -q '^OnFailure=fleet-agent-rollback.service$' "$tmp/fleet-agent.service"; then
    echo "check-unit: $unit does not start fleet-agent-rollback.service on failure" >&2
    exit 1
fi

systemd-analyze --version | head -n 1
if ! output=$(systemd-analyze verify --man=no "$tmp/fleet-agent.service" "$tmp/fleet-agent-rollback.service" 2>&1) || [ -n "$output" ]; then
    printf '%s\n' "$output" >&2
    echo "check-unit: systemd-analyze verify reported problems with $unit or $rollback_unit" >&2
    exit 1
fi
echo "systemd-analyze verify: no problems"

systemd-analyze security --offline=yes --no-pager --threshold="$max_exposure" "$tmp/fleet-agent.service"
