#!/bin/bash
# Agent soak test (P1-A09, NFR-3, FR-1.2, FR-1.6): the installed agent runs for days against a stand-in
# server that goes down and flaps, takes one update and one forced rollback, and must not leak memory,
# descriptors, threads, or state-directory space, nor restart itself.
#
#   sudo SOAK_DISPOSABLE=yes scripts/soak.sh DIR OUT        (run from agent/)
#
# DIR is prepared as for scripts/update-smoke.sh (docs/operations/agent-soak.md): test.key, a throwaway
# minisign key, and fleet-agent-1.0.0 and fleet-agent-1.0.1, the musl agent built to trust it. OUT receives
# samples.csv (one row per sample), events.log (what the test did, when), summary.md (the verdict from
# scripts/soak-analyse.py), and the agent's journal. Like update-smoke.sh it rewrites /usr/lib/fleet-agent,
# /etc/fleet-agent, /var/lib/fleet-agent and two units, so it runs only on a disposable machine with systemd.
#
# Timeline (SOAK_HOURS, default 72):
#   start     1.0.0 installed and running, heartbeat every 10 s, inventory every 60 s
#   update    at UPDATE_AT, the server offers 1.0.1 (a real build): it must be installed and confirmed
#   rollback  at ROLLBACK_AT, it offers 1.0.2, which crash-loops: it must be rolled back to 1.0.1
#   steady    from then to the end, in cycles of SOAK_CYCLE_MINUTES (default 240): the server is down for
#             SOAK_OUTAGE_SECONDS (600), flaps up and down every 30 s for SOAK_FLAP_SECONDS (600), and is
#             up for the rest of the cycle
# Every SOAK_SAMPLE_SECONDS (60), and as an update or rollback starts and ends, a sample records the agent's main PID, version, systemd restart count, resident
# memory, open descriptors, threads, state-directory size and entries, and installed versions.
set -euo pipefail

dir=${1:?usage: sudo SOAK_DISPOSABLE=yes scripts/soak.sh DIR OUT}
out=${2:?usage: sudo SOAK_DISPOSABLE=yes scripts/soak.sh DIR OUT}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=update-test-lib.sh
. "$here/update-test-lib.sh"
agent_dir=$(dirname "$here")

HOURS=${SOAK_HOURS:-72}
SAMPLE=${SOAK_SAMPLE_SECONDS:-60}
CYCLE=$((${SOAK_CYCLE_MINUTES:-240} * 60))
OUTAGE=${SOAK_OUTAGE_SECONDS:-600}
FLAP=${SOAK_FLAP_SECONDS:-600}
FLAP_PERIOD=30
# The update and the rollback come early, so most of the run is one uninterrupted agent process to measure.
TOTAL=$(awk -v h="$HOURS" 'BEGIN { printf "%d", h * 3600 }')
if [ "$TOTAL" -ge 7200 ]; then UPDATE_AT=1800 ROLLBACK_AT=3600; else UPDATE_AT=$((TOTAL * 15 / 100)) ROLLBACK_AT=$((TOTAL * 30 / 100)); fi
STEP_TIMEOUT=900 # an update or a rollback must be over within 15 minutes

LIB=/usr/lib/fleet-agent
ETC=/etc/fleet-agent
STATE=/var/lib/fleet-agent
UNITS=/etc/systemd/system
OLD=1.0.0
NEW=1.0.1
LOOPING=1.0.2
PORT=8443

[ "$(id -u)" = 0 ] || { echo "soak: run as root (sudo)" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "soak: needs a host running systemd" >&2; exit 2; }
if [ "${GITHUB_ACTIONS:-}" != true ] && [ "${SOAK_DISPOSABLE:-}" != yes ]; then
    echo "soak: this rewrites $LIB, $ETC, $STATE and $UNITS; run it on a disposable machine and set SOAK_DISPOSABLE=yes" >&2
    exit 2
fi
for path in "$LIB" "$ETC" "$STATE" "$UNITS/fleet-agent.service" "$UNITS/fleet-agent-rollback.service"; do
    [ ! -e "$path" ] || { echo "soak: $path exists; an agent is installed here, and this test would destroy it" >&2; exit 2; }
done
for file in test.key "fleet-agent-$OLD" "fleet-agent-$NEW"; do
    [ -s "$dir/$file" ] || { echo "soak: missing $dir/$file" >&2; exit 2; }
done
for tool in jq minisign openssl python3; do
    command -v "$tool" > /dev/null || { echo "soak: needs $tool" >&2; exit 2; }
done

mkdir -p "$out"
out=$(cd "$out" && pwd)
tmp=$(mktemp -d)
stub_pid=
rollout=0
since=0
events=$tmp/events.jsonl
: > "$events"
log=$out/events.log
: > "$log"
samples=$out/samples.csv

note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$log"; }

fail() {
    note "FAILED: $*"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::error title=soak::$*"
    exit 1
}

cleanup() {
    status=$?
    journalctl -u fleet-agent -u fleet-agent-update -u fleet-agent-rollback --no-pager -o short-iso > "$out/journal.log" 2>&1 || true
    tail -n 200 "$events" > "$out/server-events-tail.jsonl" 2>/dev/null || true
    systemctl stop fleet-agent-update fleet-agent fleet-agent-rollback 2>/dev/null || true
    systemctl reset-failed fleet-agent fleet-agent-update fleet-agent-rollback 2>/dev/null || true
    stop_server
    rm -rf "$LIB" "$ETC" "$STATE" "$UNITS/fleet-agent.service" "$UNITS/fleet-agent-rollback.service" "$tmp"
    systemctl daemon-reload 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT

# --- The stand-in server --------------------------------------------------------------------------------

server_up() { [ -n "$stub_pid" ]; }

start_server() {
    server_up && return
    python3 "$here/update-stub.py" "$PORT" "$tmp/cert.pem" "$tmp/key.pem" "$tmp" &
    stub_pid=$!
    until (exec 3<> "/dev/tcp/127.0.0.1/$PORT") 2> /dev/null; do
        kill -0 "$stub_pid" 2> /dev/null || fail "the stand-in server did not start"
        sleep 0.2
    done
}

stop_server() {
    server_up || return 0
    kill "$stub_pid" 2> /dev/null || true
    wait "$stub_pid" 2> /dev/null || true
    stub_pid=
}

set_plan() {
    printf '%s' "$1" > "$tmp/plan.json.new"
    mv "$tmp/plan.json.new" "$tmp/plan.json"
}

# offer RELEASE VERSION: the server offers a release, as a new rollout, until the agent reports the result.
offer() {
    rollout=$((rollout + 1))
    since=$(date +%s.%N)
    set_plan "$(jq -nc --argjson id "$rollout" --arg version "$2" --arg release "$1" '{directive: {rollout_id: $id, version: $version, release: $release}}')"
}

event_exists() { jq -e -s "$1" "$events" > /dev/null 2>&1; }
result_outcome() {
    jq -rs "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout)] | last | .body.outcome // empty" "$events"
}
heartbeat_from() {
    event_exists "[.[] | select(.kind == \"heartbeat\" and .agent_version == \"$1\" and .status == 200 and .at > $since)] | length > 0"
}
running_version() { basename "$(readlink -f "$LIB/current")"; }

# --- Sampling -------------------------------------------------------------------------------------------

phase=start

sample() {
    local pid version restarts rss='' fds='' threads='' state_bytes state_entries versions
    pid=$(systemctl show -p MainPID --value fleet-agent)
    version=$(running_version)
    restarts=$(systemctl show -p NRestarts --value fleet-agent)
    if [ "$pid" != 0 ] && [ -r "/proc/$pid/status" ]; then
        rss=$(awk '/^VmRSS:/ { print $2 }' "/proc/$pid/status")
        threads=$(awk '/^Threads:/ { print $2 }' "/proc/$pid/status")
        fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)
    fi
    state_bytes=$(du -sb "$STATE" | cut -f 1)
    state_entries=$(find "$STATE" -mindepth 1 | wc -l)
    versions=$(find "$LIB/versions" -mindepth 1 -maxdepth 1 | wc -l)
    echo "$(date +%s),$(($(date +%s) - start)),$phase,$pid,$version,$restarts,$rss,$fds,$threads,$state_bytes,$state_entries,$versions,$(server_up && echo 1 || echo 0)" >> "$samples"
}

# --- Setup ----------------------------------------------------------------------------------------------

# Certificates outlive the run with two days to spare: an expired one would end the soak's contact with the
# server partway through, and the rest of the run would measure an agent that cannot report.
make_certs "$tmp" localhost $((TOTAL / 86400 + 3))
mkdir -p "$tmp/releases"
mkrelease "$tmp/releases" good "$NEW" "$dir/fleet-agent-$NEW" "$dir/test.key"
mkscript "$tmp/loops.sh" "$LOOPING" 'echo "soak: release '"$LOOPING"' started" >&2; sleep 2; exit 1'
mkrelease "$tmp/releases" crash_loop "$LOOPING" "$tmp/loops.sh" "$dir/test.key"
set_plan '{}'
start_server

# The installed layout, as `fleet-agent install` leaves it, with 1.0.0 and the real unit files.
install -D -m 0755 "$dir/fleet-agent-$OLD" "$LIB/versions/$OLD/fleet-agent"
ln -s "versions/$OLD" "$LIB/current"
install -d -m 0700 "$ETC"
install -m 0644 "$tmp/ca.pem" "$ETC/ca.pem"
(
    umask 077
    cat > "$ETC/config.toml" << EOF
server_url = "https://localhost:$PORT"
credential = "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001"
ca_file = "$ETC/ca.pem"
log_level = "info"
update_confirm_seconds = 60

[heartbeat]
interval_seconds = 10
min_seconds = 10
max_seconds = 60

[inventory]
interval_seconds = 60
min_seconds = 60
max_seconds = 600
EOF
)
install -m 0644 "$agent_dir/src/install/fleet-agent.service" "$UNITS/fleet-agent.service"
install -m 0644 "$agent_dir/src/install/fleet-agent-rollback.service" "$UNITS/fleet-agent-rollback.service"
systemctl daemon-reload
echo "epoch,elapsed_s,phase,pid,version,restarts,rss_kib,fds,threads,state_bytes,state_entries,versions,server_up" > "$samples"

start=$(date +%s)
end=$((start + TOTAL))
systemctl start fleet-agent
note "soak: $HOURS h, update at ${UPDATE_AT}s, rollback at ${ROLLBACK_AT}s, outage cycle ${CYCLE}s (down ${OUTAGE}s, flapping ${FLAP}s)"

# --- The run --------------------------------------------------------------------------------------------

next_sample=$start
step_started=0
settled=0
while :; do
    now=$(date +%s)
    ((now < end)) || break
    elapsed=$((now - start))

    case $phase in
        start)
            if ((elapsed >= UPDATE_AT)); then
                offer good "$NEW"
                phase=update step_started=$now
                note "offered $NEW (rollout $rollout)"
                sample
            fi
            ;;
        update | rollback)
            outcome=$(result_outcome)
            expected=succeeded
            [ "$phase" = update ] || expected=rolled_back
            if [ -n "$outcome" ] && [ "$outcome" != "$expected" ]; then
                fail "$phase: the agent reported $outcome, expected $expected"
            fi
            if [ "$outcome" = "$expected" ] && [ "$(running_version)" = "$NEW" ] && heartbeat_from "$NEW" \
                && systemctl is-active --quiet fleet-agent; then
                set_plan '{}'
                note "$phase over: $outcome, $NEW running"
                sample # still labelled with this phase, so the restart it caused is attributed to it
                if [ "$phase" = update ]; then
                    phase=between
                else
                    phase=steady settled=$now
                fi
            elif ((now - step_started > STEP_TIMEOUT)); then
                fail "$phase did not finish within ${STEP_TIMEOUT}s (outcome: ${outcome:-none}, running $(running_version))"
            fi
            ;;
        between)
            if ((elapsed >= ROLLBACK_AT)); then
                offer crash_loop "$LOOPING"
                phase=rollback step_started=$now
                note "offered crash-looping $LOOPING (rollout $rollout)"
                sample
            fi
            ;;
        steady | outage | flap)
            into=$(((now - settled) % CYCLE))
            if ((into < OUTAGE)); then
                want=outage
            elif ((into < OUTAGE + FLAP)); then
                want=flap
            else
                want=steady
            fi
            [ "$want" = "$phase" ] || note "server: $want"
            phase=$want
            case $phase in
                outage) stop_server ;;
                flap) if (((into / FLAP_PERIOD) % 2)); then start_server; else stop_server; fi ;;
                steady) start_server ;;
            esac
            ;;
    esac

    if ((now >= next_sample)); then
        sample
        next_sample=$((next_sample + SAMPLE))
    fi
    sleep 1
done

start_server
sample
note "run over after $(($(date +%s) - start))s"
case $phase in
    start | update | between | rollback) fail "the run ended before the update and the rollback were done (phase $phase)" ;;
esac

# Clean-up after the update and the rollback (ADR 0018): only the versions current and previous point to
# remain, and nothing is left of the staging, the backup, the marker, the record, or the result. Problems are
# collected rather than fatal, so the leak analysis below always runs and both verdicts are reported.
problems=()
installed=$(find "$LIB/versions" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')
linked=$(for link in current previous; do basename "$(readlink "$LIB/$link")"; done | sort -u | tr '\n' ' ')
[ "$installed" = "$linked" ] || problems+=("installed versions are '$installed', expected only current and previous: '$linked'")
for leftover in "$STATE/update.json" "$STATE/update-confirmed.json" "$STATE/update-result.json" "$LIB/versions/$LOOPING"; do
    [ ! -e "$leftover" ] || problems+=("$leftover was left behind")
done
[ -z "$(find "$STATE/update" -mindepth 1 2> /dev/null)" ] || problems+=("staging or backup files were left in $STATE/update")
note "clean-up: $installed installed (current and previous: $linked); ${#problems[@]} problem(s)"

analysis=0
python3 "$here/soak-analyse.py" "$samples" "$out/summary.md" --hours "$HOURS" --sample-seconds "$SAMPLE" || analysis=$?
if [ "${#problems[@]}" -gt 0 ]; then
    { echo; echo "## Clean-up"; echo; printf -- '- [ ] %s\n' "${problems[@]}"; } >> "$out/summary.md"
    for problem in "${problems[@]}"; do note "clean-up: $problem"; done
fi
if [ "$analysis" != 0 ] || [ "${#problems[@]}" != 0 ]; then
    fail "the soak did not pass (analysis exit $analysis, ${#problems[@]} clean-up problem(s)); see summary.md"
fi
