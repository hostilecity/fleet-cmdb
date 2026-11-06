#!/bin/bash
# Failure tests of agent updates on a disposable Debian 13 VM (P1-AGENT-UPDATE, P1-A12, ADR 0018):
# the supervisor killed, and the VM restarted, in the middle of an update. Run by the CI workflow
# .github/workflows/agent-vm.yml on a GitHub runner:
#
#   scripts/vm-test.sh DIR IMAGE OUT      (run from agent/, as the runner user; no sudo)
#
# DIR holds what the workflow prepared: test.key (a throwaway minisign key, never committed) and
# fleet-agent-1.0.0 and fleet-agent-1.0.1, the musl agent built to trust it (update-smoke-build.sh).
# IMAGE is Debian's genericcloud image, already checked against Debian's SHA512SUMS. OUT receives the
# results: results.xml (JUnit), results.md, one log per scenario, and the VM's serial console.
#
# The VM runs under QEMU with KVM when /dev/kvm is usable, and falls back to TCG (with longer
# timeouts) when not. It is configured by a cloud-init NoCloud seed with an SSH key generated here.
# scripts/update-stub.py runs on the runner as the agent API and release channel; the guest reaches it
# at QEMU's host address 10.0.2.2 under the name agent.example.lan. The agent is installed with the
# real installer (`fleet-agent install --token-stdin`), so the units, the layout, the config, and the
# credential are the ones a real install makes.
#
# Every scenario starts from 1.0.0 installed and running, and ends by checking that exactly one working
# version runs: `current` and `previous` as expected, only those versions installed, the service
# active with that version's binary and no supervisor, a heartbeat the stub acknowledged (with the
# credential the installer received), the configuration unchanged, and the state still there. It also
# checks the update result the stub received.
#
#   kill before the switch   the supervisor is killed before it switches (it is held there by a
#                            drop-in for the test); the agent starts another, which installs 1.0.1
#   kill after the switch    the supervisor is killed after the switch; 1.0.1 still ends installed
#   hard reset unconfirmed   `reboot -ff` after the switch, before 1.0.1 confirms: rolled back at boot
#   reboot after confirming  1.0.1 is confirmed, then the VM restarts: 1.0.1 is kept
#   reboot before the switch the VM restarts while the supervisor is held before the switch: reported
#                            failed, 1.0.0 runs
#   crash loop and reboot    a release that crash-loops, switched to, then the VM restarts: rolled
#                            back (by the failure hook, as nothing else runs)
set -euo pipefail

dir=${1:?usage: scripts/vm-test.sh DIR IMAGE OUT}
image=${2:?usage: scripts/vm-test.sh DIR IMAGE OUT}
out=${3:?usage: scripts/vm-test.sh DIR IMAGE OUT}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=update-test-lib.sh
. "$here/update-test-lib.sh"
# shellcheck source-path=SCRIPTDIR source=vm-test-record.sh
. "$here/vm-test-record.sh"

OLD=1.0.0
NEW=1.0.1
LOOPING=1.0.3
SERVER_NAME=agent.example.lan
PORT=8443
SSH_PORT=${VM_SSH_PORT:-2222}
CREDENTIAL="EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001"
ENROLL_TOKEN="EXAMPLE-enrollment-token-not-real-0001"
LIB=/usr/lib/fleet-agent
STATE=/var/lib/fleet-agent
HOLD=/run/fleet-agent-update-hold
DROPIN=/etc/systemd/system/fleet-agent-update.service.d
# A state record the agent never writes: the backup before a switch must carry it, and a rollback must
# put back exactly what it held, so a lost or skipped backup shows as a difference.
MARKER=vm-test-marker.json

for file in test.key "fleet-agent-$OLD" "fleet-agent-$NEW"; do
    [ -s "$dir/$file" ] || { echo "vm-test: missing $dir/$file" >&2; exit 2; }
done
[ -s "$image" ] || { echo "vm-test: missing image $image" >&2; exit 2; }
image=$(cd "$(dirname "$image")" && pwd)/$(basename "$image")
mkdir -p "$out/logs"
out=$(cd "$out" && pwd)

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    accel=kvm cpu=host slow=1
else
    accel=tcg cpu=max slow=4
    echo "vm-test: /dev/kvm is not usable; falling back to TCG (slower, timeouts x$slow)"
fi

tmp=$(mktemp -d)
stub=$tmp/stub
mkdir -p "$stub/releases"
events=$stub/events.jsonl
: > "$events"
stub_pid=
rollout=0
record_out=$out
record_tmp=$tmp

cleanup() {
    local status=$?
    set +e
    record_write "$status"
    [ ! -s "$out/results.md" ] || cat "$out/results.md"
    if [ -s "$tmp/qemu.pid" ]; then
        kill "$(cat "$tmp/qemu.pid")" 2> /dev/null || true
    fi
    [ -z "$stub_pid" ] || kill "$stub_pid" 2> /dev/null || true
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup EXIT

# --- The VM -------------------------------------------------------------------------------------------

ssh-keygen -q -t ed25519 -N '' -C "vm-test throwaway" -f "$tmp/id"
ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes
    -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -i "$tmp/id")

# vm COMMAND: runs COMMAND as root in the guest, with bash.
vm() {
    ssh "${ssh_opts[@]}" -p "$SSH_PORT" tester@127.0.0.1 "sudo bash -c $(printf '%q' "$1")"
}
vm_ok() { vm "$1" > /dev/null 2>&1; }
put() { scp -q "${ssh_opts[@]}" -P "$SSH_PORT" "$1" "tester@127.0.0.1:$2"; }
boot_id() { vm 'cat /proc/sys/kernel/random/boot_id' 2> /dev/null; }

cat > "$tmp/user-data" << EOF
#cloud-config
hostname: vm-01
fqdn: vm-01.example.lan
manage_etc_hosts: false
ssh_pwauth: false
users:
  - name: tester
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$tmp/id.pub")
write_files:
  - path: /etc/hosts
    content: |
      127.0.0.1 localhost
      127.0.1.1 vm-01.example.lan vm-01
      10.0.2.2 $SERVER_NAME
EOF
printf 'instance-id: vm-test-01\nlocal-hostname: vm-01\n' > "$tmp/meta-data"
genisoimage -quiet -output "$tmp/seed.iso" -volid cidata -joliet -rock "$tmp/user-data" "$tmp/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$tmp/disk.qcow2" 8G

qemu-system-x86_64 -name vm-01 -machine "q35,accel=$accel" -cpu "$cpu" -m 2048 -smp 2 \
    -drive "file=$tmp/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=$tmp/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" -device virtio-net-pci,netdev=net0 \
    -display none -serial "file:$out/console.log" -daemonize -pidfile "$tmp/qemu.pid"

# --- Waiting, reporting -------------------------------------------------------------------------------

wait_until() {
    local what=$1 seconds=$(($2 * slow)) end
    shift 2
    end=$((SECONDS + seconds))
    until "$@"; do
        ((SECONDS < end)) || fail "gave up after ${seconds}s waiting for $what"
        sleep 1
    done
}

ssh_up() { vm_ok true; }

# booted_since BOOT_ID: the VM answers, from a boot other than BOOT_ID.
booted_since() {
    local now
    now=$(boot_id) || return 1
    [ -n "$now" ] && [ "$now" != "$1" ]
}

# reboot_vm soft|hard: `systemctl reboot`, or `reboot -ff` (no sync, no unmount: a reset), then waits
# for SSH from the new boot.
reboot_vm() {
    local before
    before=$(boot_id)
    [ -n "$before" ] || fail "cannot read the boot id before the reboot"
    case $1 in
        soft) vm 'systemctl reboot' > /dev/null 2>&1 || true ;;
        hard) timeout 10 ssh "${ssh_opts[@]}" -p "$SSH_PORT" tester@127.0.0.1 'sudo reboot -ff' > /dev/null 2>&1 || true ;;
    esac
    wait_until "the VM to come back after a $1 reboot" 300 booted_since "$before"
    echo "rebooted ($1); boot id $(boot_id)"
}

event_exists() { jq -e -s "$1" "$events" > /dev/null 2>&1; }
heartbeat_from() {
    event_exists "[.[] | select(.kind == \"heartbeat\" and .agent_version == \"$1\" and .status == 200 and .at > $since)] | length > 0"
}
result_accepted() {
    event_exists "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout)] | length > 0"
}
accepted_result() {
    jq -cs "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout)] | last" "$events"
}

set_plan() {
    printf '%s' "$1" > "$stub/plan.json.new"
    mv "$stub/plan.json.new" "$stub/plan.json"
}

# offer RELEASE VERSION [EXTRA_PLAN_JSON]: the server starts offering a release for rollout $rollout.
offer() {
    local extra=${3:-}
    [ -n "$extra" ] || extra='{}'
    set_plan "$(jq -nc --argjson id "$rollout" --arg version "$2" --arg release "$1" --argjson extra "$extra" \
        '{directive: {rollout_id: $id, version: $version, release: $release}} + $extra')"
}

link_of() { vm "readlink $LIB/$1 || true" 2> /dev/null; }
current_is() { [ "$(link_of current)" = "versions/$1" ]; }

# hold_supervisor on|off: a drop-in that makes the supervisor's unit wait, before it does anything,
# while $HOLD exists. Test scaffolding only: it lets a scenario stop an update before the switch.
hold_supervisor() {
    case $1 in
        on)
            vm "mkdir -p $DROPIN && printf '%s\n' '[Service]' 'ExecStart=' \
'ExecStart=/bin/sh -c \"while [ -e $HOLD ]; do sleep 0.2; done; exec $LIB/versions/$OLD/fleet-agent update-supervise --config /etc/fleet-agent/config.toml\"' \
> $DROPIN/hold.conf && touch $HOLD && systemctl daemon-reload"
            ;;
        off) vm "rm -f $HOLD; rm -rf $DROPIN; systemctl daemon-reload" ;;
    esac
}

held_before_switch() {
    vm_ok "systemctl is-active --quiet fleet-agent-update && grep -Eq '\"phase\": ?\"staged\"' $STATE/update.json \
        && systemctl show -p ExecStart fleet-agent-update | grep -q fleet-agent-update-hold"
}

# reset: 1.0.0 installed and running, no update in progress, the stub offering nothing.
reset() {
    wait_until "SSH" 300 ssh_up
    set_plan '{}'
    vm "systemctl stop fleet-agent-update fleet-agent fleet-agent-rollback 2>/dev/null || true
        systemctl reset-failed fleet-agent fleet-agent-update fleet-agent-rollback 2>/dev/null || true
        rm -f $HOLD; rm -rf $DROPIN; systemctl daemon-reload
        find $LIB/versions -mindepth 1 -maxdepth 1 ! -name $OLD -exec rm -rf {} +
        rm -f $LIB/previous
        ln -sfn versions/$OLD $LIB/current
        rm -rf $STATE/update $STATE/update.json $STATE/update-confirmed.json $STATE/update-result.json $STATE/update.lock
        systemctl start fleet-agent"
    since=$(date +%s.%N)
    wait_until "a heartbeat from $OLD" 90 heartbeat_from "$OLD"
    marker_original="rollout $rollout: state $OLD wrote before the update ($(date +%s%N))"
    write_marker "$marker_original"
    marker_expected=$marker_original
}

write_marker() {
    vm "printf '%s' $(printf '%q' "$1") > $STATE/$MARKER && chmod 0600 $STATE/$MARKER && sync"
}

# change_state: the state changes while the new version runs (after the backup was taken). A rollback
# must undo this; a confirmed update must keep it.
change_state() {
    marker_changed="rollout $rollout: state changed while the new version ran"
    write_marker "$marker_changed"
}

# The update has settled: no update record, no outcome waiting to be posted, no supervisor or rollback
# unit running, and the service active. Prints what has not settled yet.
unsettled() {
    vm "s=''
        [ ! -e $STATE/update.json ] || s=\"\$s the update record $STATE/update.json is still there;\"
        [ ! -e $STATE/update-result.json ] || s=\"\$s the outcome in $STATE/update-result.json is not yet accepted;\"
        for u in fleet-agent-update fleet-agent-rollback; do
            a=\$(systemctl show -p ActiveState --value \$u)
            case \$a in inactive|failed|'') ;; *) s=\"\$s \$u is \$a;\" ;; esac
        done
        a=\$(systemctl show -p ActiveState --value fleet-agent)
        [ \"\$a\" = active ] || s=\"\$s fleet-agent is \$a;\"
        printf '%s' \"\$s\"" 2> /dev/null || echo " the VM does not answer;"
}


# wait_settled: an accepted result is published before the supervisor cleans up and restarts the service,
# so the final layout is inspected only once the update has settled.
wait_settled() {
    local seconds=$((180 * slow)) end left
    end=$((SECONDS + seconds))
    while true; do
        left=$(unsettled)
        [ -n "$left" ] || return 0
        ((SECONDS < end)) || fail "the update did not settle within ${seconds}s:$left"
        sleep 1
    done
}

# expect_result OUTCOME REPORTER [REASON_TEXT]: the update result the stub accepted for this rollout.
expect_result() {
    local result outcome reporter reason
    wait_until "the update result" 300 result_accepted
    result=$(accepted_result)
    outcome=$(jq -r '.body.outcome' <<< "$result")
    reporter=$(jq -r '.agent_version' <<< "$result")
    reason=$(jq -r '.body.reason // ""' <<< "$result")
    echo "result: $outcome, reported by $reporter${reason:+: $reason}"
    printf '%s' "$outcome${reason:+: $reason}" > "$tmp/last-result"
    [ "$outcome" = "$1" ] || fail "the result is $outcome, expected $1"
    [ "$reporter" = "$2" ] || fail "the result was reported by $reporter, expected $2"
    if [ -n "${3:-}" ]; then
        [[ $reason == *"$3"* ]] || fail "the reason does not mention \"$3\": $reason"
    fi
}

# expect_one_version VERSION PREVIOUS: exactly one working version runs (PREVIOUS "-" means no link).
expect_one_version() {
    local version=$1 previous=$2 installed expected pid exe runs t marker
    wait_settled
    [ "$(link_of current)" = "versions/$version" ] || fail "current is $(link_of current), expected versions/$version"
    if [ "$previous" = - ]; then
        [ -z "$(link_of previous)" ] || fail "previous is $(link_of previous), expected none"
        expected=$version
    else
        [ "$(link_of previous)" = "versions/$previous" ] || fail "previous is $(link_of previous), expected versions/$previous"
        expected=$(printf '%s\n' "$version" "$previous" | sort -u | tr '\n' ' ')
    fi
    installed=$(vm "ls $LIB/versions" | sort -u | tr '\n' ' ')
    expected=$(printf '%s\n' "$expected" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')
    [ "$installed" = "$expected" ] || fail "installed versions are '$installed', expected '$expected'"
    pid=$(vm 'systemctl show -p MainPID --value fleet-agent')
    exe=$(vm "readlink /proc/$pid/exe")
    [ "$exe" = "$LIB/versions/$version/fleet-agent" ] || fail "the service runs $exe, expected version $version"
    runs=$(vm "pgrep -c -f '^$LIB/current/fleet-agent run' || true")
    [ "$runs" = 1 ] || fail "$runs agent processes run, expected 1"
    t=$(date +%s.%N)
    since=$t
    wait_until "a heartbeat from $version acknowledged by the server" 90 heartbeat_from "$version"
    [ "$(vm 'sha256sum /etc/fleet-agent/config.toml')" = "$config_sum" ] || fail "the configuration (and credential) changed"
    for file in $state_files; do
        vm_ok "test -s $STATE/$file" || fail "$STATE/$file is gone"
    done
    marker=$(vm "cat $STATE/$MARKER" 2> /dev/null || echo "(missing)")
    [ "$marker" = "$marker_expected" ] \
        || fail "the state record $MARKER holds '$marker', expected '$marker_expected' (state lost, or not restored by the rollback)"
    event_exists '[.[] | select(.kind == "unauthorised")] | length == 0' || fail "the stub saw a request without the credential"
    echo "one version runs: $version (previous: $previous); heartbeat acknowledged; configuration and credential unchanged; state record as expected"
}

# --- Setup --------------------------------------------------------------------------------------------

make_certs "$tmp" "$SERVER_NAME"
mkrelease "$stub/releases" good "$NEW" "$dir/fleet-agent-$NEW" "$dir/test.key"
mkscript "$tmp/loops.sh" "$LOOPING" "echo \"vm-test: release $LOOPING started\" >&2; sleep 2; exit 1"
mkrelease "$stub/releases" crash_loop "$LOOPING" "$tmp/loops.sh" "$dir/test.key"

STUB_PUBLIC_URL="https://$SERVER_NAME:$PORT" STUB_CREDENTIAL="$CREDENTIAL" STUB_ENROLL_TOKEN="$ENROLL_TOKEN" \
    python3 "$here/update-stub.py" "$PORT" "$tmp/cert.pem" "$tmp/key.pem" "$stub" &
stub_pid=$!

echo "vm-test: booting Debian 13 ($accel)"
started=$SECONDS
since=0
wait_until "SSH on the first boot" 300 ssh_up
vm 'cloud-init status --wait > /dev/null || true'
# shellcheck disable=SC2016 # expanded in the guest
echo "vm-test: booted in $((SECONDS - started))s: $(vm '. /etc/os-release; echo "$PRETTY_NAME, $(uname -r)"')"

# Journals from earlier boots are wanted when a scenario fails after a reboot.
vm 'mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal && systemctl restart systemd-journald'
put "$dir/fleet-agent-$OLD" /tmp/fleet-agent
put "$tmp/ca.pem" /tmp/ca.pem
echo "vm-test: installing $OLD with the real installer"
vm "printf '%s\n' '$ENROLL_TOKEN' | /tmp/fleet-agent install --server https://$SERVER_NAME:$PORT --ca-file /tmp/ca.pem --token-stdin"
# Shorter intervals than production, so the test takes minutes: a heartbeat every 10 s and a minute to
# confirm an update.
vm "printf '%s\n' '' 'update_confirm_seconds = 60' '' '[heartbeat]' 'interval_seconds = 10' 'min_seconds = 10' 'max_seconds = 60' \
    >> /etc/fleet-agent/config.toml && $LIB/current/fleet-agent check-config > /dev/null && systemctl restart fleet-agent"
config_sum=$(vm 'sha256sum /etc/fleet-agent/config.toml')
state_files=$(vm "cd $STATE && ls -p | grep -v / | grep -v '^update' | tr '\n' ' '")
echo "vm-test: installed; state files: $state_files"

# --- Scenarios ----------------------------------------------------------------------------------------

kill_before_switch() {
    rollout=$1
    reset
    hold_supervisor on
    offer good "$NEW"
    wait_until "the supervisor to start and be held before the switch" 120 held_before_switch
    current_is "$OLD" || fail "switched while held"
    vm 'systemctl kill --signal=SIGKILL fleet-agent-update'
    wait_until "the killed supervisor to be gone" 30 vm_ok '! systemctl is-active --quiet fleet-agent-update'
    vm_ok "test -e $STATE/update.json" || fail "the update record is gone after the kill"
    current_is "$OLD" || fail "current changed by the kill"
    hold_supervisor off
    expect_result succeeded "$NEW"
    expect_one_version "$NEW" "$OLD"
}

kill_after_switch() {
    rollout=$1
    reset
    offer good "$NEW" "{\"slow_heartbeat\": {\"version\": \"$NEW\", \"seconds\": 8}}"
    wait_until "the switch to $NEW" 120 current_is "$NEW"
    vm 'systemctl kill --signal=SIGKILL fleet-agent-update' || fail "no supervisor to kill"
    change_state
    expect_result succeeded "$NEW"
    # A confirmed update keeps what the new version wrote.
    marker_expected=$marker_changed
    expect_one_version "$NEW" "$OLD"
}

reset_after_switch() {
    rollout=$1
    reset
    # The new version's heartbeats are answered late, so it cannot confirm before the reset.
    offer good "$NEW" "{\"slow_heartbeat\": {\"version\": \"$NEW\", \"seconds\": 20}}"
    wait_until "the switch to $NEW" 120 current_is "$NEW"
    change_state
    reboot_vm hard
    expect_result rolled_back "$OLD" "restarted"
    # The rollback restores the state backed up before the switch, and `previous` as it was (none).
    expect_one_version "$OLD" -
}

reboot_after_confirmation() {
    rollout=$1
    reset
    offer good "$NEW"
    expect_result succeeded "$NEW"
    wait_settled
    change_state
    marker_expected=$marker_changed
    reboot_vm soft
    expect_one_version "$NEW" "$OLD"
    local results
    results=$(jq -s "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout) | .body.outcome] | unique | join(\",\")" "$events")
    [ "$results" = '"succeeded"' ] || fail "results for the rollout after the reboot: $results"
}

reboot_before_switch() {
    rollout=$1
    reset
    hold_supervisor on
    offer good "$NEW"
    wait_until "the supervisor to start and be held before the switch" 120 held_before_switch
    reboot_vm soft
    expect_result failed "$OLD" "restarted"
    hold_supervisor off
    expect_one_version "$OLD" -
}

crash_loop_and_reboot() {
    rollout=$1
    reset
    offer crash_loop "$LOOPING"
    wait_until "the switch to $LOOPING" 120 current_is "$LOOPING"
    change_state
    reboot_vm soft
    expect_result rolled_back "$OLD" "restarted"
    expect_one_version "$OLD" - # `previous` put back as it was before the update (none)
    vm "journalctl -b -u fleet-agent-rollback --no-pager -o cat" | grep -q "update supervisor finished" \
        || fail "the failure hook did not run after the reboot"
}

# --- Running and recording (vm-test-record.sh) -------------------------------------------------------

diagnostics() {
    echo "--- layout and state"
    vm "ls -l $LIB $LIB/versions $STATE; cat $STATE/update.json 2>/dev/null" 2>&1 || echo "(the VM does not answer)"
    echo "--- journals (this boot and the one before)"
    for b in -1 0; do
        vm "journalctl -b $b --no-pager -o short-iso -u fleet-agent -u fleet-agent-update -u fleet-agent-rollback | tail -n 80" 2>&1 || true
    done
    echo "--- what the stub saw (last 30)"
    tail -n 30 "$events"
}

os="Debian 13"
record_header() {
    echo "## Agent update failure tests on a VM (P1-A12)"
    echo
    echo "$os under QEMU ($accel), image $(basename "$image"); agent $OLD updated to $NEW (and $LOOPING, a crash-looping release); installed with \`fleet-agent install\`."
    echo "Each scenario ends by checking that exactly one working version runs (links, installed versions, the service's binary, one agent process, no supervisor or update record left, an acknowledged heartbeat), that the configuration and credential are unchanged, and that a state record holds exactly what it should: kept after a confirmed update, restored by a rollback."
}

scenario 301 "Supervisor killed before the switch" kill_before_switch
scenario 302 "Supervisor killed after the switch" kill_after_switch
scenario 303 "Hard reset after the switch, before confirmation" reset_after_switch
scenario 304 "Reboot after confirmation" reboot_after_confirmation
scenario 305 "Reboot before the switch" reboot_before_switch
scenario 306 "Crash-looping release across a reboot" crash_loop_and_reboot

# shellcheck disable=SC2016 # expanded in the guest
os=$(vm '. /etc/os-release; echo "$PRETTY_NAME"' 2> /dev/null || echo "Debian 13")
# The EXIT trap writes results.xml and results.md.
[ "$record_failed" = 0 ]
