#!/bin/bash
# End to end test of the agent's supervised update and automatic rollback on a real systemd
# (P1-AGENT-UPDATE, ADR 0018): the real unit files, the real side-by-side layout, a real `systemd-run`
# from inside the agent's sandbox, and releases signed with throwaway keys.
#
#   sudo scripts/update-smoke.sh DIR [GROUP]    (run from agent/)
#
# GROUP runs one part, so CI can run the parts side by side: refusals (the four refused releases), rollbacks
# (exits at start, crash loop, no credential), recovery (both killed supervisors, success, below minimum), or
# limits (the memory and task limits, #182). Without it, every scenario runs.
#
# DIR holds what the workflow prepared (scripts/update-smoke-build.sh, minisign -G -W): test.key and
# other.key (throwaway private keys, never committed), and fleet-agent-1.0.0 and fleet-agent-1.0.1, the
# musl agent built to trust test.pub. It changes /usr/lib/fleet-agent, /etc/fleet-agent, /var/lib/fleet-agent
# and /etc/systemd/system, so it refuses to run anywhere but a disposable machine (GITHUB_ACTIONS=true or
# UPDATE_SMOKE_DISPOSABLE=yes) and anywhere an agent is already installed.
#
# A stand-in for the API and the release channel (scripts/update-stub.py) offers an update the way the
# server does, and records what the agent sends. Every scenario starts from the same installed 1.0.0:
#
#   refused        a tampered binary, an unsigned manifest, one signed by a key the agent does not know, and
#                  an older version are refused; the running version is unchanged and the refusal is reported
#   exits at start a release that passes its self-test and then exits: rolled back and reported
#   crash loop     the same, for one that fails again and again
#   no credential  a real 1.0.1 whose heartbeats are rejected (it never confirms): rolled back and reported
#   killed         the supervisor killed with SIGKILL after the switch: a good release still ends installed,
#                  and a crash-looping one is rolled back by the OnFailure unit
#   success        a good release is installed, keeps the configuration, reports in its first inventory, and
#                  its result is retried until the server accepts it
#   below minimum  an agent the server answers 426 on inventory still updates (NFR-5)
#   limits         (#182) the unit's memory and task limits are in force; a release that leaks is held by them
#                  and rolled back; an agent killed for memory is restarted
#                  cleanly; and one killed at every start ends in recovery mode, which keeps reporting, and
#                  is normal again once the limit is raised. The limit is lowered with a drop-in, as an
#                  operator would raise it.
set -euo pipefail

dir=${1:?usage: sudo scripts/update-smoke.sh DIR [refusals|rollbacks|recovery|limits]}
group=${2:-all}
case "$group" in
    all | refusals | rollbacks | recovery | limits) ;;
    *) echo "update-smoke: unknown group $group (refusals, rollbacks, recovery, or limits)" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=update-test-lib.sh
. "$here/update-test-lib.sh"
agent_dir=$(dirname "$here")
[ "$(id -u)" = 0 ] || { echo "update-smoke: run as root (sudo)" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "update-smoke: needs a host running systemd" >&2; exit 2; }

LIB=/usr/lib/fleet-agent
ETC=/etc/fleet-agent
STATE=/var/lib/fleet-agent
UNITS=/etc/systemd/system
OLD=1.0.0
NEW=1.0.1

if [ "${GITHUB_ACTIONS:-}" != true ] && [ "${UPDATE_SMOKE_DISPOSABLE:-}" != yes ]; then
    echo "update-smoke: this rewrites $LIB, $ETC, $STATE and $UNITS; run it on a disposable machine and set UPDATE_SMOKE_DISPOSABLE=yes" >&2
    exit 2
fi
for path in "$LIB" "$ETC" "$STATE" "$UNITS/fleet-agent.service" "$UNITS/fleet-agent.service.d" "$UNITS/fleet-agent-rollback.service" "$UNITS/fleet-agent-recovery.service"; do
    if [ -e "$path" ]; then
        echo "update-smoke: $path exists; an agent is installed here, and this test would destroy it" >&2
        exit 2
    fi
done
for file in test.key other.key "fleet-agent-$OLD" "fleet-agent-$NEW"; do
    [ -s "$dir/$file" ] || { echo "update-smoke: missing $dir/$file" >&2; exit 2; }
done

tmp=$(mktemp -d)
stub_pid=
rollout=100
since=0
events=$tmp/events.jsonl
: > "$events"

# --- Reporting a failure ------------------------------------------------------------------------------

diagnostics() {
    for unit in fleet-agent fleet-agent-update fleet-agent-rollback fleet-agent-recovery; do
        echo "--- journal: $unit"
        journalctl -u "$unit" --no-pager -o cat 2>&1 | tail -n 60
    done
    echo "--- layout"
    ls -l "$LIB" "$LIB/versions" 2>&1 || true
    echo "--- $STATE"
    ls -l "$STATE" 2>&1 || true
    echo "--- update.json"
    cat "$STATE/update.json" 2>&1 || true
    echo "--- what the stub saw (last 40)"
    tail -n 40 "$events" 2>&1 || true
}

fail() {
    echo "update-smoke: FAILED: $*" >&2
    out=$(diagnostics 2>&1) || true
    printf '%s\n' "$out"
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        body=$(printf '%s\n' "$out" | tail -n 80 | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')
        echo "::error title=update-smoke: $*::$body"
    fi
    exit 1
}

cleanup() {
    systemctl stop fleet-agent-update fleet-agent fleet-agent-rollback fleet-agent-recovery 2>/dev/null || true
    systemctl reset-failed fleet-agent fleet-agent-update fleet-agent-rollback fleet-agent-recovery 2>/dev/null || true
    [ -z "$stub_pid" ] || kill "$stub_pid" 2>/dev/null || true
    rm -rf "$LIB" "$ETC" "$STATE" "$UNITS/fleet-agent.service" "$UNITS/fleet-agent-rollback.service" "$UNITS/fleet-agent-recovery.service" "$tmp" \
        "$UNITS/fleet-agent.service.d" "$UNITS/multi-user.target.wants/fleet-agent.service"
    systemctl daemon-reload 2>/dev/null || true
}
trap cleanup EXIT

# --- Helpers ------------------------------------------------------------------------------------------

set_plan() {
    printf '%s' "$1" > "$tmp/plan.json.new"
    mv "$tmp/plan.json.new" "$tmp/plan.json"
}

# offer RELEASE VERSION [EXTRA_PLAN_JSON]: the server starts offering a release, as a new rollout.
offer() {
    local extra=${3:-}
    [ -n "$extra" ] || extra='{}'
    rollout=$((rollout + 1))
    set_plan "$(jq -nc --argjson id "$rollout" --arg version "$2" --arg release "$1" --argjson extra "$extra" \
        '{directive: {rollout_id: $id, version: $version, release: $release}} + $extra')"
}

wait_until() {
    local what=$1 seconds=$2 end
    shift 2
    end=$((SECONDS + seconds))
    until "$@"; do
        ((SECONDS < end)) || fail "gave up after ${seconds}s waiting for $what"
        sleep 1
    done
}

running_version() { basename "$(readlink -f "$LIB/current")"; }
service_active() { systemctl is-active --quiet fleet-agent; }
event_exists() { jq -e -s "$1" "$events" > /dev/null 2>&1; }

heartbeat_from() {
    event_exists "[.[] | select(.kind == \"heartbeat\" and .agent_version == \"$1\" and .status == 200 and .at > $since)] | length > 0"
}
result_accepted() {
    event_exists "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout)] | length > 0"
}
inventory_from() {
    event_exists "[.[] | select(.kind == \"inventory\" and .agent_version == \"$1\" and .status == ${2:-200} and .at > $since)] | length > 0"
}
running_is() { [ "$(running_version)" = "$1" ]; }
recovery_stopped() { ! systemctl is-active --quiet fleet-agent-recovery; }
# journal_has UNIT TEXT: TEXT was logged by UNIT since the scenario started (an earlier scenario may have
# logged the same).
journal_has() { journalctl -u "$1" --since "@${since%.*}" --no-pager -o cat 2> /dev/null | grep -Fq -- "$2"; }

# result_field FIELD: a field of the accepted result of the current rollout.
result_field() {
    jq -rs "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout)] | last | .body.$1" "$events"
}

# release NAME VERSION BINARY [KEY]: a signed release for the stub to serve (update-test-lib.sh).
release() {
    mkrelease "$tmp/releases" "$1" "$2" "$3" "${4:-$dir/test.key}"
}

# reset: the installed 1.0.0 running, no update in progress, the stub offering nothing.
reset() {
    systemctl stop fleet-agent-update fleet-agent fleet-agent-rollback fleet-agent-recovery 2>/dev/null || true
    systemctl reset-failed fleet-agent fleet-agent-update fleet-agent-rollback fleet-agent-recovery 2>/dev/null || true
    find "$LIB/versions" -mindepth 1 -maxdepth 1 ! -name "$OLD" -exec rm -rf {} +
    rm -f "$LIB/previous"
    ln -sfn "versions/$OLD" "$LIB/current"
    rm -rf "$STATE/update" "$STATE/update.json" "$STATE/update-confirmed.json" "$STATE/update-result.json" "$STATE/update.lock"
    set_plan '{}'
    since=$(date +%s.%N)
    systemctl start fleet-agent
    wait_until "a heartbeat from $OLD" 60 heartbeat_from "$OLD"
}

# A refusal or rollback leaves the old version running and reports why. The recovery unit the same OnFailure=
# starts after the rollback unit finds the service running again and exits (ADR 0030), so recovery mode never
# runs beside it.
expect_old_running() {
    running_is "$OLD" || fail "$1: the running version is $(running_version), not $OLD"
    service_active || fail "$1: the service is not active"
    wait_until "$1: recovery mode to see the service running and exit" 30 recovery_stopped
    since=$(date +%s.%N)
    wait_until "$1: a heartbeat from $OLD after the result" 60 heartbeat_from "$OLD"
}

expect_result() { # SCENARIO OUTCOME [AGENT_VERSION]
    local outcome reporter reason
    outcome=$(result_field outcome)
    reporter=$(jq -rs "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout)] | last | .agent_version" "$events")
    reason=$(result_field reason)
    echo "$1: reported $outcome by $reporter: $reason"
    [ "$outcome" = "$2" ] || fail "$1: the result is $outcome, expected $2"
    [ -z "${3:-}" ] || [ "$reporter" = "$3" ] || fail "$1: the result was reported by $reporter, expected $3"
    if [ "$2" != succeeded ]; then
        if [ -z "$reason" ] || [ "$reason" = null ]; then
            fail "$1: no reason was given"
        fi
    fi
}

# --- Setup --------------------------------------------------------------------------------------------

# A throwaway CA and a localhost server certificate it signs (as scripts/sandbox-smoke.sh does).
make_certs "$tmp" localhost

# The releases the stub serves.
mkdir -p "$tmp/releases"
release good "$NEW" "$dir/fleet-agent-$NEW"
release tampered "$NEW" "$dir/fleet-agent-$NEW"
printf 'tampered-by-the-test' | dd of="$tmp/releases/tampered/fleet-agent" bs=1 seek=4096 conv=notrunc 2> /dev/null
release unsigned "$NEW" "$dir/fleet-agent-$NEW"
printf 'this is not a signature\n' > "$tmp/releases/unsigned/manifest.json.minisig"
release unknown_key "$NEW" "$dir/fleet-agent-$NEW" "$dir/other.key"
mkscript "$tmp/older.sh" 0.9.0 'exit 0'
release older 0.9.0 "$tmp/older.sh"
mkscript "$tmp/exits.sh" 1.0.2 'echo "update-smoke: release 1.0.2 refuses to start" >&2; exit 1'
release exits_at_start 1.0.2 "$tmp/exits.sh"
mkscript "$tmp/loops.sh" 1.0.3 'echo "update-smoke: release 1.0.3 started" >&2; sleep 2; exit 1'
release crash_loop 1.0.3 "$tmp/loops.sh"
# A release that leaks: tail keeps the last 400 MiB of its input, more than the unit's MemoryMax. The kernel
# throttles it once it passes MemoryHigh, so it creeps towards MemoryMax (agent/contrib/README.md).
mkscript "$tmp/leaks.sh" 1.0.4 'echo "update-smoke: release 1.0.4 started" >&2; head -c 400M /dev/zero | tail -c 400M > /dev/null; sleep 60'
release leaks 1.0.4 "$tmp/leaks.sh"

python3 "$here/update-stub.py" 8443 "$tmp/cert.pem" "$tmp/key.pem" "$tmp" &
stub_pid=$!
until (exec 3<> /dev/tcp/127.0.0.1/8443) 2> /dev/null; do
    kill -0 "$stub_pid" 2> /dev/null || fail "the stand-in server did not start"
    sleep 0.2
done

# The installed layout, as `fleet-agent install` leaves it, with 1.0.0 and the real unit files.
install -D -m 0755 "$dir/fleet-agent-$OLD" "$LIB/versions/$OLD/fleet-agent"
ln -s "versions/$OLD" "$LIB/current"
install -d -m 0700 "$ETC"
install -m 0644 "$tmp/ca.pem" "$ETC/ca.pem"
(
    umask 077
    cat > "$ETC/config.toml" <<EOF
server_url = "https://localhost:8443"
credential = "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001"
ca_file = "$ETC/ca.pem"
log_level = "debug"
update_confirm_seconds = 15

[heartbeat]
interval_seconds = 10
min_seconds = 10
max_seconds = 60
EOF
)
install -m 0644 "$agent_dir/src/install/fleet-agent.service" "$UNITS/fleet-agent.service"
install -m 0644 "$agent_dir/src/install/fleet-agent-rollback.service" "$UNITS/fleet-agent-rollback.service"
install -m 0644 "$agent_dir/src/install/fleet-agent-recovery.service" "$UNITS/fleet-agent-recovery.service"
systemctl daemon-reload
config_before=$(sha256sum "$ETC/config.toml" "$ETC/ca.pem")

# --- Scenarios ----------------------------------------------------------------------------------------

in_group() { [ "$group" = all ] || [ "$group" = "$1" ]; }

refused() { # RELEASE VERSION
    echo "== refused: $1 ($2)"
    reset
    offer "$1" "$2"
    wait_until "the refusal of $1 to be reported" 90 result_accepted
    expect_result "refused $1" failed "$OLD"
    expect_old_running "refused $1"
    [ ! -e "$LIB/versions/$2" ] || fail "refused $1: $LIB/versions/$2 exists"
}
if in_group refusals; then
    refused tampered "$NEW"
    refused unsigned "$NEW"
    refused unknown_key "$NEW"
    refused older 0.9.0
fi

rolled_back() { # SCENARIO RELEASE VERSION [EXTRA_PLAN]
    echo "== rolled back: $1"
    reset
    offer "$2" "$3" "${4:-}"
    wait_until "$1 to be rolled back and reported" 180 result_accepted
    expect_result "$1" rolled_back "$OLD"
    expect_old_running "$1"
}
if in_group rollbacks; then
    rolled_back "a release that exits at start" exits_at_start 1.0.2
    rolled_back "a crash-looping release" crash_loop 1.0.3
    rolled_back "a release that cannot authenticate" good "$NEW" "{\"deny_heartbeat\": [\"$NEW\"]}"
fi


# --- The memory and task limits (#182) ------------------------------------------------------------------

DROPIN=$UNITS/fleet-agent.service.d/50-update-smoke-limit.conf

# lower_memory_max VALUE: a drop-in, as `systemctl edit fleet-agent` writes one; daemon-reload applies it to
# the running service's cgroup at once.
lower_memory_max() {
    mkdir -p "$(dirname "$DROPIN")"
    printf '[Service]\nMemoryMax=%s\n' "$1" > "$DROPIN"
    systemctl daemon-reload
}
remove_dropin() {
    rm -f "$DROPIN"
    rmdir "$(dirname "$DROPIN")" 2> /dev/null || true
    systemctl daemon-reload
}
# oom_killed [SINCE]: systemd logged an OOM kill of the service since SINCE (default: the scenario's start).
oom_killed() {
    journalctl -u fleet-agent --since "@${1:-${since%.*}}" --no-pager -o cat 2> /dev/null | grep -Fq "oom-kill"
}
restarts() { systemctl show fleet-agent -p NRestarts --value; }
recovery_heartbeat() {
    event_exists "[.[] | select(.kind == \"heartbeat\" and .status == 200 and .recovery != null and .at > $since)] | length > 0"
}
normal_heartbeat() {
    event_exists "[.[] | select(.kind == \"heartbeat\" and .agent_version == \"$OLD\" and .status == 200 and .recovery == null and .at > $since)] | length > 0"
}

if in_group limits; then
    echo "== limits: in force on the installed unit"
    reset
    want=$(unit_limits "$UNITS/fleet-agent.service")
    for unit in fleet-agent fleet-agent-recovery; do
        shown=$(systemctl show "$unit" -p MemoryHigh -p MemoryMax -p MemorySwapMax -p OOMPolicy -p TasksMax | sort | tr '\n' ' ' | sed 's/ $//')
        [ "$shown" = "$want" ] || fail "limits: $unit has '$shown', expected '$want'"
        echo "limits: $unit: $shown"
    done
    # The rollback unit must never be stopped by a limit: it acts after the service failed, perhaps for one.
    shown=$(systemctl show fleet-agent-rollback -p MemoryMax -p TasksMax | sort | tr '\n' ' ')
    case "$shown" in
        "MemoryMax=infinity TasksMax="*) ;;
        *) fail "limits: the rollback unit has '$shown', expected no memory limit" ;;
    esac
    cgroup=/sys/fs/cgroup$(systemctl show fleet-agent -p ControlGroup --value)
    echo "limits: the running agent: memory.current $(cat "$cgroup/memory.current"), memory.peak $(cat "$cgroup/memory.peak" 2> /dev/null || echo unknown), pids.current $(cat "$cgroup/pids.current")"

    # The new version leaks before it confirms. The kernel holds it in the service's cgroup (throttled past
    # MemoryHigh, killed at MemoryMax), and the supervisor and the rollback unit, which run outside that
    # cgroup, roll it back: at the confirmation deadline, or once the service fails. A sampler records the
    # cgroup's memory events meanwhile, as proof that the limit, not luck, held the leak.
    leak_since=$(date +%s)
    (
        set +eo pipefail
        while :; do
            cg=/sys/fs/cgroup$(systemctl show fleet-agent -p ControlGroup --value 2> /dev/null)
            { cat "$cg/memory.current" "$cg/memory.events"; } 2> /dev/null | tr '\n' ' '
            echo
            sleep 0.2
        done
    ) > "$tmp/leak-samples" &
    sampler=$!
    rolled_back "a release that leaks 400 MiB" leaks 1.0.4
    kill "$sampler" 2> /dev/null || true
    journalctl -u fleet-agent --since "@$leak_since" --no-pager -o cat | grep -Fq "update-smoke: release 1.0.4 started" \
        || fail "leaking release: 1.0.4 never ran"
    held=$(awk '{ for (i = 2; i < NF; i++) if (($i == "high" || $i == "oom_kill") && $(i + 1) > 0) n++ } END { print n + 0 }' "$tmp/leak-samples")
    most=$(awk 'BEGIN { m = 0 } $1 ~ /^[0-9]+$/ && $1 > m { m = $1 } END { print m }' "$tmp/leak-samples")
    if [ "$held" = 0 ] && ! oom_killed "$leak_since"; then
        fail "leaking release: the cgroup never reached MemoryHigh or MemoryMax (largest sample $most bytes)"
    fi
    [ "$most" -le "$(sed -n 's/^MemoryMax=//p' "$UNITS/fleet-agent.service" | sed 's/M$//' | awk '{ print $1 * 1048576 }')" ] \
        || fail "leaking release: the cgroup held $most bytes, more than MemoryMax"
    echo "limits: the leaking release was held below MemoryMax (largest sample $most bytes, $held samples past MemoryHigh) and rolled back$(oom_killed "$leak_since" && echo ', after an OOM kill')"

    echo "== limits: killed for memory, then restarted cleanly"
    reset
    before=$(restarts)
    since=$(date +%s.%N)
    # Far below what the agent uses, so the kernel kills it at its next allocation.
    lower_memory_max 1M
    wait_until "the OOM kill of the running agent" 60 oom_killed
    remove_dropin
    since=$(date +%s.%N)
    wait_until "a heartbeat from the restarted agent" 90 heartbeat_from "$OLD"
    service_active || fail "killed for memory: the service is not active"
    [ "$(restarts)" -gt "$before" ] || fail "killed for memory: systemd did not restart it (NRestarts $(restarts))"
    recovery_stopped || fail "killed for memory: recovery mode runs after a single kill"
    [ -f "$STATE/task-ledger.jsonl" ] || fail "killed for memory: the task ledger is gone"
    [ ! -e "$STATE/update.json" ] || fail "killed for memory: an update record appeared"
    echo "limits: killed for memory and restarted by systemd ($(restarts) restarts); heartbeat, ledger, and state intact"

    echo "== limits: killed at every start: start limit, then recovery mode, then normal again"
    reset
    # Recovery mode stays only for a service that is still enabled (ADR 0030).
    systemctl enable --quiet fleet-agent
    since=$(date +%s.%N)
    lower_memory_max 1M
    wait_until "recovery mode to report" 240 recovery_heartbeat
    reason=$(jq -rs "[.[] | select(.kind == \"heartbeat\" and .recovery != null and .at > $since)] | last | .recovery.reason" "$events")
    echo "limits: recovery mode reports: $reason"
    [ "$(systemctl is-active fleet-agent)" = failed ] || fail "killed at every start: the service is $(systemctl is-active fleet-agent), not failed"
    oom_killed || fail "killed at every start: no OOM kill was logged"
    [ ! -e "$STATE/update.json" ] || fail "killed at every start: the rollback unit left an update record"
    # The operator raises the limit again and starts the service (troubleshooting.md).
    remove_dropin
    systemctl reset-failed fleet-agent
    since=$(date +%s.%N)
    systemctl start fleet-agent
    wait_until "recovery mode to see the service running and exit" 30 recovery_stopped
    wait_until "a heartbeat in normal mode" 90 normal_heartbeat
    service_active || fail "killed at every start: the service is not active after the limit was raised"
    systemctl disable --quiet fleet-agent
    echo "limits: an agent killed at every start stayed reachable in recovery mode, and is normal again"
fi
in_group limits && [ "$group" = limits ] && { echo "update-smoke: every $group scenario passed"; exit 0; }

in_group recovery || { echo "update-smoke: every $group scenario passed"; exit 0; }

echo "== killed: the supervisor dies after the switch of a good release"
reset
offer good "$NEW" "{\"slow_heartbeat\": {\"version\": \"$NEW\", \"seconds\": 8}}"
wait_until "the switch to $NEW" 90 running_is "$NEW"
systemctl kill --signal=SIGKILL fleet-agent-update || fail "no supervisor to kill"
wait_until "the update to be finished and reported" 180 result_accepted
expect_result "killed supervisor, good release" succeeded "$NEW"
running_is "$NEW" || fail "killed supervisor, good release: running $(running_version)"
service_active || fail "killed supervisor, good release: the service is not active"

echo "== killed: the supervisor dies after the switch to a crash-looping release"
reset
offer crash_loop 1.0.3
wait_until "release 1.0.3 to start" 90 journal_has fleet-agent "update-smoke: release 1.0.3 started"
systemctl kill --signal=SIGKILL fleet-agent-update || fail "no supervisor to kill"
wait_until "the rollback unit to roll it back and the agent to report" 240 result_accepted
expect_result "killed supervisor, crash-looping release" rolled_back "$OLD"
journal_has fleet-agent-rollback "update supervisor finished ended=RolledBack" \
    || fail "the rollback was not done by the OnFailure rollback unit"
expect_old_running "killed supervisor, crash-looping release"

echo "== success: a good release is installed, refreshes the units, and its result is retried"
reset
# #232: units from before recovery mode (no recovery unit, OnFailure= names only the rollback unit); the confirmed
# update writes the new version's.
sed -e 's/^OnFailure=fleet-agent-rollback.service fleet-agent-recovery.service$/OnFailure=fleet-agent-rollback.service/' \
    -e '/^RestartMode=direct$/d' "$agent_dir/src/install/fleet-agent.service" > "$UNITS/fleet-agent.service"
rm -f "$UNITS/fleet-agent-recovery.service"
systemctl daemon-reload
offer good "$NEW" '{"results_503": 2}'
wait_until "the update to be reported" 150 result_accepted
expect_result "success" succeeded "$NEW"
[ "$(result_field reason)" = null ] || fail "success: the result has a reason: $(result_field reason)"
for unit in fleet-agent.service fleet-agent-recovery.service; do
    cmp -s "$agent_dir/src/install/$unit" "$UNITS/$unit" || fail "success: $UNITS/$unit is not the new version's"
done
systemctl show -p OnFailure --value fleet-agent | grep -q fleet-agent-recovery.service || fail "success: systemd was not reloaded"
running_is "$NEW" || fail "success: running $(running_version)"
[ "$(readlink "$LIB/previous")" = "versions/$OLD" ] || fail "success: previous is $(readlink "$LIB/previous"), not versions/$OLD"
since=$(date +%s.%N)
wait_until "a heartbeat from $NEW" 60 heartbeat_from "$NEW"
wait_until "a heartbeat from $NEW that says recovery mode is set up" 60 \
    event_exists "[.[] | select(.kind == \"heartbeat\" and .agent_version == \"$NEW\" and .units.recovery == true and .at > $since)] | length > 0"
statuses=$(jq -rs "[.[] | select(.kind == \"result\" and .body.rollout_id == $rollout) | .status] | map(tostring) | join(\",\")" "$events")
[ "$statuses" = "503,503,200" ] || fail "success: the result was posted with statuses $statuses, expected 503,503,200"
[ "$(sha256sum "$ETC/config.toml" "$ETC/ca.pem")" = "$config_before" ] || fail "success: the configuration changed"
for file in heartbeat.json inventory.json; do
    [ -s "$STATE/$file" ] || fail "success: $STATE/$file is missing after the update"
done
since=0
# The updated agent restarted with an inventory record, so its startup report waits a splay of up to 60 s (#200).
wait_until "inventory from $NEW" 90 inventory_from "$NEW"

echo "== below minimum: an agent the server answers 426 still updates (NFR-5)"
reset
set_plan "{\"min_version\": \"$NEW\"}"
since=$(date +%s.%N)
# A first start (no inventory record), so the startup inventory is not held back by the restart splay (#200).
systemctl stop fleet-agent && rm -f "$STATE/inventory.json" && systemctl start fleet-agent
wait_until "inventory to be refused with 426" 60 inventory_from "$OLD" 426
offer good "$NEW" "{\"min_version\": \"$NEW\"}"
wait_until "the update to be reported" 150 result_accepted
expect_result "below minimum" succeeded "$NEW"
running_is "$NEW" || fail "below minimum: running $(running_version)"
# The new version's startup inventory (since is still from before the update; inventory is every 15 min). The
# update restarted it with an inventory record, so the report waits a splay of up to 60 s (#200).
wait_until "inventory from $NEW to be accepted" 150 inventory_from "$NEW" 200

echo "update-smoke: every $group scenario passed"
