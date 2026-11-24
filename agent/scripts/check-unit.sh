#!/bin/sh
# Checks the agent's systemd unit with systemd-analyze (P1-PACKAGING), as CI does:
#
#   scripts/check-unit.sh [UNIT [ROLLBACK_UNIT [RECOVERY_UNIT]]]
#       (default: src/install/fleet-agent.service and the fleet-agent-rollback.service and
#       fleet-agent-recovery.service beside it, run from agent/)
#
# 1. `systemd-analyze verify` must print nothing for the service and the rollback and recovery units its
#    OnFailure= starts (P1-AGENT-UPDATE, ADR 0030), checked together: an unknown or misspelt option, a value systemd cannot
#    parse, or an OnFailure= naming a unit that is not there is only a warning to systemd, so any output
#    fails the check, except warnings about other unit files of the machine it runs on (systemd 259 warns
#    about removed options in the stock units of Ubuntu 26.04), which are printed but not held against ours.
# 2. `systemd-analyze security` prints the exposure table of the service and fails above MAX_EXPOSURE (on
#    its 0-100 scale; 20 is an overall exposure of 2.0), so weakening the sandbox fails CI. The rollback
#    unit is not held to it: it has to change /usr/lib/fleet-agent and restart the service.
# 3. The recovery unit runs the agent too (recovery mode, ADR 0030), so it is held to the same threshold
#    and its exposure must be no higher than the service's: recovery mode gains no privilege.
#
# The ExecStart= (and the service's ExecStopPost=) binaries are swapped for /bin/true, since the agent is not installed where this runs.
set -eu

unit=${1:-src/install/fleet-agent.service}
rollback_unit=${2:-$(dirname "$unit")/fleet-agent-rollback.service}
recovery_unit=${3:-$(dirname "$unit")/fleet-agent-recovery.service}
max_exposure=${MAX_EXPOSURE:-20}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed -e 's#^ExecStart=/usr/lib/fleet-agent/current/fleet-agent #ExecStart=/bin/true #' \
    -e 's#^ExecStopPost=-/usr/lib/fleet-agent/current/fleet-agent #ExecStopPost=-/bin/true #' "$unit" \
    > "$tmp/fleet-agent.service"
if ! grep -q '^ExecStart=/bin/true run$' "$tmp/fleet-agent.service"; then
    echo "check-unit: ExecStart= is not /usr/lib/fleet-agent/current/fleet-agent run" >&2
    exit 1
fi
# #251: how the agent stopped is recorded by the same binary, and never fails the stop ("-").
if ! grep -q '^ExecStopPost=-/bin/true note-stop$' "$tmp/fleet-agent.service"; then
    echo "check-unit: ExecStopPost= is not -/usr/lib/fleet-agent/current/fleet-agent note-stop" >&2
    exit 1
fi

sed 's#^ExecStart=/usr/lib/fleet-agent/previous/fleet-agent #ExecStart=/bin/true #' "$rollback_unit" \
    > "$tmp/fleet-agent-rollback.service"
if ! grep -q '^ExecStart=/bin/true update-rollback --reason crash-loop$' "$tmp/fleet-agent-rollback.service"; then
    echo "check-unit: ExecStart= is not /usr/lib/fleet-agent/previous/fleet-agent update-rollback --reason crash-loop" >&2
    exit 1
fi
sed 's#^ExecStart=/usr/lib/fleet-agent/current/fleet-agent #ExecStart=/bin/true #' "$recovery_unit" \
    > "$tmp/fleet-agent-recovery.service"
if ! grep -q '^ExecStart=/bin/true run --recovery$' "$tmp/fleet-agent-recovery.service"; then
    echo "check-unit: ExecStart= is not /usr/lib/fleet-agent/current/fleet-agent run --recovery" >&2
    exit 1
fi
if ! grep -q '^OnFailure=fleet-agent-rollback.service fleet-agent-recovery.service$' "$tmp/fleet-agent.service"; then
    echo "check-unit: $unit does not start fleet-agent-rollback.service and then fleet-agent-recovery.service on failure" >&2
    exit 1
fi

systemd-analyze --version | head -n 1
status=0
output=$(systemd-analyze verify --man=no "$tmp/fleet-agent.service" "$tmp/fleet-agent-rollback.service" \
    "$tmp/fleet-agent-recovery.service" 2>&1) || status=$?
# A line that starts with another unit file's path ("/usr/lib/systemd/system/x.service:26: ...") is about
# that file; anything else, including lines that name no file, counts against ours.
others=$(printf '%s\n' "$output" | awk -v ours="$tmp/" 'NF && /^\/[^:]*:/ && index($0, ours) != 1')
output=$(printf '%s\n' "$output" | awk -v ours="$tmp/" 'NF && !(/^\/[^:]*:/ && index($0, ours) != 1)')
if [ -n "$others" ]; then
    printf 'check-unit: ignored, about other unit files on this machine:\n%s\n' "$others"
fi
if [ "$status" -ne 0 ] || [ -n "$output" ]; then
    printf '%s\n' "$output" >&2
    echo "check-unit: systemd-analyze verify reported problems with $unit, $rollback_unit, or $recovery_unit" >&2
    exit 1
fi
echo "systemd-analyze verify: no problems"

systemd-analyze security --offline=yes --no-pager --threshold="$max_exposure" "$tmp/fleet-agent.service"
systemd-analyze security --offline=yes --no-pager --threshold="$max_exposure" "$tmp/fleet-agent-recovery.service" \
    | tail -n 1
# "→ Overall exposure level for x.service: 1.9 OK :-)": the number, times ten, as an integer.
exposure() {
    systemd-analyze security --offline=yes --no-pager "$1" | tail -n 1 \
        | sed -n 's/.*: \([0-9]*\)\.\([0-9]\).*/\1\2/p'
}
service_exposure=$(exposure "$tmp/fleet-agent.service")
recovery_exposure=$(exposure "$tmp/fleet-agent-recovery.service")
if [ -z "$service_exposure" ] || [ -z "$recovery_exposure" ]; then
    echo "check-unit: cannot read the exposure levels" >&2
    exit 1
fi
if [ "$recovery_exposure" -gt "$service_exposure" ]; then
    echo "check-unit: the recovery unit's exposure ($recovery_exposure/100) is higher than the service's ($service_exposure/100)" >&2
    exit 1
fi
echo "recovery unit exposure $recovery_exposure/100, no higher than the service's $service_exposure/100"
