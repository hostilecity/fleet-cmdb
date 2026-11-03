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
# shellcheck source=update-test-lib.sh
. "$here/update-test-lib.sh"

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

cleanup() {
    if [ -s "$tmp/qemu.pid" ]; then
        kill "$(cat "$tmp/qemu.pid")" 2> /dev/null || true
    fi
    [ -z "$stub_pid" ] || kill "$stub_pid" 2> /dev/null || true
    rm -rf "$tmp"
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

# fail MESSAGE: ends the scenario (scenarios run in a subshell).
fail() {
    echo "vm-test: FAILED: $*" >&2
    exit 1
}

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
    new_boot() {
        local now
        now=$(boot_id) || return 1
        [ -n "$now" ] && [ "$now" != "$before" ]
    }
    wait_until "the VM to come back after a $1 reboot" 300 new_boot
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
    local version=$1 previous=$2 installed expected pid exe runs t
    # The service may be on its way back up after the result was sent.
    wait_until "the service to be active" 120 vm_ok 'systemctl is-active --quiet fleet-agent'
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
    vm_ok 'systemctl is-active --quiet fleet-agent-update' && fail "an update supervisor is still running"
    wait_until "no update in progress" 120 vm_ok "test ! -e $STATE/update.json"
    t=$(date +%s.%N)
    since=$t
    wait_until "a heartbeat from $version acknowledged by the server" 90 heartbeat_from "$version"
    [ "$(vm 'sha256sum /etc/fleet-agent/config.toml')" = "$config_sum" ] || fail "the configuration (and credential) changed"
    for file in $state_files; do
        vm_ok "test -s $STATE/$file" || fail "$STATE/$file is gone"
    done
    event_exists '[.[] | select(.kind == "unauthorised")] | length == 0' || fail "the stub saw a request without the credential"
    echo "one version runs: $version (previous: $previous); heartbeat acknowledged; configuration and state kept"
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
    reset
    offer good "$NEW" "{\"slow_heartbeat\": {\"version\": \"$NEW\", \"seconds\": 8}}"
    wait_until "the switch to $NEW" 120 current_is "$NEW"
    vm 'systemctl kill --signal=SIGKILL fleet-agent-update' || fail "no supervisor to kill"
    expect_result succeeded "$NEW"
    expect_one_version "$NEW" "$OLD"
}

reset_after_switch() {
    reset
    # The new version's heartbeats are answered late, so it cannot confirm before the reset.
    offer good "$NEW" "{\"slow_heartbeat\": {\"version\": \"$NEW\", \"seconds\": 20}}"
    wait_until "the switch to $NEW" 120 current_is "$NEW"
    reboot_vm hard
    expect_result rolled_back "$OLD" "restarted"
    expect_one_version "$OLD" "$OLD"
}

reboot_after_confirmation() {
    reset
    offer good "$NEW"
    expect_result succeeded "$NEW"
    reboot_vm soft
    expect_one_version "$NEW" "$OLD"
    local results
    results=$(jq -s "[.[] | select(.kind == \"result\" and .status == 200 and .body.rollout_id == $rollout) | .body.outcome] | unique | join(\",\")" "$events")
    [ "$results" = '"succeeded"' ] || fail "results for the rollout after the reboot: $results"
}

reboot_before_switch() {
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
    reset
    offer crash_loop "$LOOPING"
    wait_until "the switch to $LOOPING" 120 current_is "$LOOPING"
    reboot_vm soft
    expect_result rolled_back "$OLD" "restarted"
    expect_one_version "$OLD" "$OLD"
    vm "journalctl -b -u fleet-agent-rollback --no-pager -o cat" | grep -q "update supervisor finished" \
        || fail "the failure hook did not run after the reboot"
}

# --- Running and recording ----------------------------------------------------------------------------

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

passed=0
failed=0
cases=
rows=

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

# scenario ROLLOUT NAME FUNCTION: runs one scenario in a subshell and records it.
scenario() {
    local id=$1 name=$2 fn=$3 start log status message
    start=$SECONDS
    log=$out/logs/$fn.log
    rm -f "$tmp/last-result"
    echo "== $name"
    set +e
    (
        set -e
        rollout=$id
        "$fn"
    ) 2>&1 | tee "$log"
    status=${PIPESTATUS[0]}
    set -e
    local took=$((SECONDS - start)) result=""
    [ -s "$tmp/last-result" ] && result=$(cat "$tmp/last-result")
    if [ "$status" = 0 ]; then
        passed=$((passed + 1))
        cases+="  <testcase classname=\"agent-update-vm\" name=\"$(printf '%s' "$name" | xml_escape)\" time=\"$took\"/>"$'\n'
        rows+="| $name | passed | $result | ${took}s |"$'\n'
    else
        failed=$((failed + 1))
        message=$(grep 'vm-test: FAILED' "$log" | tail -n 1 | sed 's/^vm-test: FAILED: //')
        diagnostics >> "$log" 2>&1 || true
        cases+="  <testcase classname=\"agent-update-vm\" name=\"$(printf '%s' "$name" | xml_escape)\" time=\"$took\"><failure message=\"$(printf '%s' "$message" | xml_escape)\"/></testcase>"$'\n'
        rows+="| $name | **failed**: $message | $result | ${took}s |"$'\n'
        if [ -n "${GITHUB_ACTIONS:-}" ]; then
            echo "::error title=vm-test: $name::$message (see logs/$fn.log in the vm-test-results artifact)"
        fi
    fi
}

scenario 301 "Supervisor killed before the switch" kill_before_switch
scenario 302 "Supervisor killed after the switch" kill_after_switch
scenario 303 "Hard reset after the switch, before confirmation" reset_after_switch
scenario 304 "Reboot after confirmation" reboot_after_confirmation
scenario 305 "Reboot before the switch" reboot_before_switch
scenario 306 "Crash-looping release across a reboot" crash_loop_and_reboot

os=$(vm '. /etc/os-release; echo "$PRETTY_NAME"' 2> /dev/null || echo "Debian 13")
{
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<testsuite name="agent-update-vm" tests="%s" failures="%s" time="%s">\n' "$((passed + failed))" "$failed" "$SECONDS"
    printf '%s' "$cases"
    printf '</testsuite>\n'
} > "$out/results.xml"
{
    echo "## Agent update failure tests on a VM (P1-A12)"
    echo
    echo "$os under QEMU ($accel), image $(basename "$image"); agent $OLD updated to $NEW (and $LOOPING, a crash-looping release); installed with \`fleet-agent install\`."
    echo "Each scenario ends by checking that exactly one working version runs (links, installed versions, the service's binary, one agent process, no supervisor, an acknowledged heartbeat) and that the configuration, credential, and state survived."
    echo
    echo "| Scenario | Outcome | Update result | Time |"
    echo "| --- | --- | --- | --- |"
    printf '%s' "$rows"
    echo
    echo "$passed passed, $failed failed, in ${SECONDS}s."
} > "$out/results.md"
cat "$out/results.md"
[ "$failed" = 0 ]
