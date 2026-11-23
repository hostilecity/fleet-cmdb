#!/bin/bash
# Failure tests of agent updates on a disposable Debian 13 VM (P1-AGENT-UPDATE, P1-A12, ADR 0018):
# the supervisor killed, and the VM restarted, in the middle of an update. Run by the CI workflow
# .github/workflows/agent-vm.yml on a GitHub runner:
#
#   scripts/vm-test.sh DIR IMAGE OUT [GROUP]      (run from agent/, as the runner user; no sudo)
#
# DIR holds what the workflow prepared: test.key (a throwaway minisign key, never committed) and the
# musl agent builds that trust it (update-smoke-build.sh), fleet-agent-VERSION, as GROUP needs them.
# IMAGE is Debian's genericcloud image, already checked against Debian's SHA512SUMS. OUT receives the
# results: results.xml (JUnit), results.md, one log per scenario, and the VM's serial console.
#
# GROUP picks the scenarios (#288). The groups are independent: each boots its own VM from the image
# and starts from the same fresh install, so CI runs them side by side, one VM each (agent-vm.yml).
#
#   all        every scenario below, in one VM, in the order below (the default)
#   install    290, 300, 309: the install refusals, the package report, what is in use (fleet-agent-1.0.0)
#   updates-a  301 to 304: the supervisor killed, a hard reset, a reboot after confirming (1.0.0, 1.0.1)
#   updates-b  305, 306, 308: a reboot before the switch, a crash loop, the units refresh (1.0.0, 1.0.1)
#   packages   370 to 373: apply_package_updates (fleet-agent-1.0.0 is the fault build here, for the
#              shorter lock wait of scenario 371; see below)
#   recovery   307: recovery mode (1.0.0, 1.1.0 the fault build, 1.1.1)
#
# Every group ends with scenario 374, the memory and task limits, for the scenarios that ran in its VM.
#
# The VM runs under QEMU with KVM when /dev/kvm is usable, and falls back to TCG (with longer
# timeouts) when not. It is configured by a cloud-init NoCloud seed with an SSH key generated here.
# scripts/update-stub.py runs on the runner as the agent API and release channel; the guest reaches it
# at QEMU's host address 10.0.2.2 under the name agent.example.lan. The agent is installed as the
# dashboard's install page says (#181): curl and minisign from Debian, the binary, manifest, and signature
# downloaded from the stub, the signature checked with minisign and the binary against the signed
# manifest, then the real installer (`fleet-agent install --token-stdin`), so the units, the layout, the
# config, and the credential are the ones a real install makes. The page fetches the release public key
# from the repository on GitHub; these releases are signed with a throwaway key, so the guest gets that
# key as the file the page's key command would write. Scenario 290 checks that the same commands refuse a
# tampered binary, a manifest signed by another key, and an older signed release, with nothing run.
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
#   units refreshed          1.0.0 runs under units from before recovery mode (no recovery unit,
#                            OnFailure= names only the rollback unit); the confirmed update to 1.0.1
#                            writes the new version's units (`install --refresh-units`, #232), reloads
#                            systemd without restarting the service again, and 1.0.1's heartbeats
#                            report units.recovery true
#
# Every scenario also checks that recovery mode (fleet-agent-recovery.service, ADR 0030) is not running
# once it settles: OnFailure= starts it only once the service has given up (RestartMode=direct), and it exits
# at once when a rollback has restarted the service.
#
# Before them, one check of the package report (P2-AGENT-PACKAGES, AC-2.3): the report the agent sends
# at startup, under the real unit on the real image, lists exactly the VM's own dpkg listing, with the
# source package of each.
#
# Then what is in use (FR-2.6, VT-APPLICABILITY, scenario 309): test services listening on loopback and on
# the VM's LAN address named by package and class, sshd on every address, the reboot flag null without
# Debian's file and true with it, a socket-activated test service (systemd holds its socket) named, no
# address or port in the report, the agent's unit unchanged; then the
# library scan enabled in the local config, its transient unit carrying CAP_SYS_PTRACE alone with no
# network, the libraries listening test services map named with their class, a library no process
# maps not listed, and one upgraded under a running program stale.
#
# After them, the apply_package_updates task (P3-AGENT-UPDATES, AC-3.4, AC-3.5), delivered by the stub
# acting as the task API, against a local repository of tiny packages built in the guest
# (scripts/vm-test-packages.sh), with Debian's own sources set aside so the run is the same every time:
#
#   packages upgraded        a real apt-get upgrade: fvt-demo moves from 1.0 to 1.1, the held fvt-held
#                            and fvt-rm (whose upgrade would remove another package) stay and are
#                            reported held back, reboot_required is reported and the VM is
#                            not rebooted, needrestart names the service running the old executable and
#                            it is not restarted, and a package report with the new version follows
#   lock contention          another process holds the dpkg frontend lock: lock_timeout, nothing run.
#                            A release waits 300 s for the lock (LOCK_WAIT, D3). In the packages group
#                            fleet-agent-1.0.0 is the fault build (`--cfg fleet_vm_fault`), which reads
#                            a shorter wait from the state directory (src/vm_fault.rs, #288), so the
#                            scenario takes seconds; scenario 370 still checks apt's own
#                            DPkg::Lock::Timeout=300, and a unit test that a release waits 300 s. In
#                            the other groups fleet-agent-1.0.0 is a normal build, and "all" waits the
#                            full 300 s.
#   agent restarted          the agent restarts during the upgrade: the upgrade runs on in its unit, and
#                            the restarted agent reports it succeeded (threat model L8)
#   forced timeout           a maintainer script that hangs, with a 60 s deadline: timed_out, the whole
#                            process tree ended, the repair guidance in the output
#
# Last, recovery mode (#180, ADR 0030), with two more builds: fleet-agent-1.1.0, the VM fault build
# (src/vm_fault.rs; `VM_FAULT=1 update-smoke-build.sh`), and fleet-agent-1.1.1, a normal build:
#
#   crash loop on a confirmed version   tasks are enabled as the package scenarios enable them, with a
#                            10 s poll, and a refused task fills the ledger; 1.1.0 is installed and
#                            confirmed, and polls for tasks; then a file in the state
#                            directory makes its normal mode panic at every start. After exactly four
#                            failed starts systemd's start limit ends the restarts; only then does
#                            OnFailure= run (once), the rollback unit finds nothing to roll back, and
#                            recovery mode goes on: heartbeats that say why,
#                            from the same binary, with no
#                            capabilities, and no report or task poll. The server offers 1.1.1 (the
#                            "fixed release"): recovery mode installs it through the signed path, 1.1.1
#                            confirms in normal mode and polls for tasks, and recovery mode has stopped.
#                            The config (with [tasks]) and the ledger come through it all unchanged.
set -euo pipefail

dir=${1:?usage: scripts/vm-test.sh DIR IMAGE OUT [GROUP]}
image=${2:?usage: scripts/vm-test.sh DIR IMAGE OUT [GROUP]}
out=${3:?usage: scripts/vm-test.sh DIR IMAGE OUT [GROUP]}
group=${4:-all}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=update-test-lib.sh
. "$here/update-test-lib.sh"
# shellcheck source-path=SCRIPTDIR source=vm-test-record.sh
. "$here/vm-test-record.sh"

OLD=1.0.0
NEW=1.0.1
LOOPING=1.0.3
FAULTY=1.1.0
FIXED=1.1.1
# The file that makes the fault build's normal mode panic (src/vm_fault.rs).
POISON=vm-test-poison
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
# The fault build's lock wait (src/vm_fault.rs LOCK_WAIT_FILE), and the seconds the packages group sets.
LOCK_WAIT_FILE=vm-test-lock-wait-seconds
LOCK_WAIT_TEST=20

# The builds each group needs, and which of them are fault builds (the rest must not be).
case $group in
    all) builds=("$OLD" "$NEW" "$FAULTY" "$FIXED") faults=("$FAULTY") ;;
    install) builds=("$OLD") faults=() ;;
    updates-a | updates-b) builds=("$OLD" "$NEW") faults=() ;;
    packages) builds=("$OLD") faults=("$OLD") ;;
    recovery) builds=("$OLD" "$FAULTY" "$FIXED") faults=("$FAULTY") ;;
    *) echo "vm-test: unknown group $group (all, install, updates-a, updates-b, packages, recovery)" >&2; exit 2 ;;
esac
for file in test.key "${builds[@]/#/fleet-agent-}"; do
    [ -s "$dir/$file" ] || { echo "vm-test: missing $dir/$file" >&2; exit 2; }
done
[ -s "$image" ] || { echo "vm-test: missing image $image" >&2; exit 2; }
# Only a fault build has the fault (scripts/check-no-fault-hooks.sh proves a release has none).
fault_marker=$(sed -n 's/^pub const FAULT_HOOK_MARKER: &str = "\(.*\)";$/\1/p' src/test_support.rs)
[ -n "$fault_marker" ] || { echo "vm-test: FAULT_HOOK_MARKER not found in src/test_support.rs" >&2; exit 2; }
for version in "${builds[@]}"; do
    if [[ " ${faults[*]} " == *" $version "* ]]; then
        grep -aqF "$fault_marker" "$dir/fleet-agent-$version" || { echo "vm-test: fleet-agent-$version is not the fault build" >&2; exit 2; }
    elif grep -aqF "$fault_marker" "$dir/fleet-agent-$version"; then
        echo "vm-test: fleet-agent-$version contains the fault" >&2
        exit 2
    fi
done
old_is_fault_build=0
[[ " ${faults[*]} " != *" $OLD "* ]] || old_is_fault_build=1
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

# wait_until WHAT SECONDS COMMAND...: runs COMMAND every second until it succeeds, for at most SECONDS
# (times the TCG factor). A wait of 5 s or more is logged, so the job log shows where a scenario's time goes.
wait_until() {
    local what=$1 seconds=$(($2 * slow)) end start=$SECONDS
    shift 2
    end=$((SECONDS + seconds))
    until "$@"; do
        ((SECONDS < end)) || fail "gave up after ${seconds}s waiting for $what"
        sleep 1
    done
    ((SECONDS - start < 5)) || echo "vm-test: waited $((SECONDS - start))s for $what"
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
    vm "systemctl stop fleet-agent-update fleet-agent fleet-agent-rollback fleet-agent-recovery 2>/dev/null || true
        systemctl reset-failed fleet-agent fleet-agent-update fleet-agent-rollback fleet-agent-recovery 2>/dev/null || true
        rm -f $HOLD; rm -rf $DROPIN; systemctl daemon-reload
        find $LIB/versions -mindepth 1 -maxdepth 1 ! -name $OLD -exec rm -rf {} +
        rm -f $LIB/previous
        ln -sfn versions/$OLD $LIB/current
        rm -rf $STATE/update $STATE/update.json $STATE/update-confirmed.json $STATE/update-result.json $STATE/update.lock
        rm -f $STATE/$POISON $STATE/recovery.json $STATE/last-failure.json
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
        for u in fleet-agent-update fleet-agent-rollback fleet-agent-recovery; do
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
    for file in $empty_state_files; do
        vm_ok "test -f $STATE/$file" || fail "$STATE/$file is gone"
    done
    for file in $state_files; do
        vm_ok "test -s $STATE/$file" || fail "$STATE/$file is gone"
    done
    marker=$(vm "cat $STATE/$MARKER" 2> /dev/null || echo "(missing)")
    [ "$marker" = "$marker_expected" ] \
        || fail "the state record $MARKER holds '$marker', expected '$marker_expected' (state lost, or not restored by the rollback)"
    event_exists '[.[] | select(.kind == "unauthorised")] | length == 0' || fail "the stub saw a request without the credential"
    echo "one version runs: $version (previous: $previous); heartbeat acknowledged; configuration and credential unchanged; state record as expected"
}

# --- The install page's commands (#181) ---------------------------------------------------------------

# Exactly the text of the dashboard's commands (cmdb/app/helpers/agent_releases_helper.rb), for a server whose
# certificate authority curl must be given, as with Cloudflare's Origin CA; cmdb/spec/requests/agent_installs_spec.rb
# fails if they drift apart. INSTALL_TOOLS runs as root, so without sudo.
INSTALL_TOOLS='apt-get update && apt-get install -y curl minisign'
# install_commands NAME: the download and check commands for the stub's release NAME (in place of the version in the
# URLs), checking for release $OLD. The page's first two lines (a new private directory, and the CA certificate from
# GitHub) are replaced by run_install_commands: the test's CA is a throwaway one, not on GitHub.
install_commands() {
    local s="https://$SERVER_NAME:$PORT" n=$1 e=${OLD//./\\.}
    cat << EOF
curl -fL --cacert fleet-server-ca.pem -o fleet-agent $s/api/v1/releases/$n/binary
curl -fL --cacert fleet-server-ca.pem -o fleet-agent.manifest.json $s/api/v1/releases/$n/manifest
curl -fL --cacert fleet-server-ca.pem -o fleet-agent.manifest.json.minisig $s/api/v1/releases/$n/signature
minisign -V -p fleet-release-key.pub -m fleet-agent.manifest.json -o | sed -n 's/^{"format":"fleet-agent-release-manifest\/1","version":"$e","target":"x86_64-unknown-linux-musl","sha256":"\([0-9a-f]\{64\}\)","size":[0-9]*}$/\1  fleet-agent/p' | sha256sum -c
EOF
}

# install_release NAME BINARY KEY [VERSION]: release VERSION (default $OLD) signed with KEY as the release workflow
# signs it (its trusted comment), as the stub's release NAME.
install_release() {
    local d=$stub/releases/$1 version=${4:-$OLD}
    mkdir -p "$d"
    cp "$2" "$d/fleet-agent"
    "$here/release-manifest.sh" "$version" "$UPDATE_TEST_TARGET" "$d/fleet-agent" > "$d/manifest.json"
    minisign -S -s "$3" -m "$d/manifest.json" -x "$d/manifest.json.minisig" \
        -t "fleet-agent $version $UPDATE_TEST_TARGET release manifest" > /dev/null
}

# run_install_commands NAME: runs install_commands NAME as root in a new /root/install-NAME in the guest, with the
# CA file and the release key the page's commands would fetch from GitHub (/root is root-only, as the page's
# `mktemp -d` directory is private). The downloads' output
# (curl's progress) goes to stderr; the check's output, which the page says it must print, to stdout.
run_install_commands() {
    local d=/root/install-$1
    vm "rm -rf $d && mkdir $d && cp /tmp/ca.pem $d/fleet-server-ca.pem && cp /tmp/release-key.pub $d/fleet-release-key.pub"
    vm "set -e; cd $d; $(install_commands "$1" | sed '$d')" >&2 2>&1
    vm "cd $d && $(install_commands "$1" | tail -n 1)" 2>&1
}

# First install (#181): the commands refuse a binary that is not the signed one, a manifest signed by a key other
# than the repository's, and an older release signed with the right key but served under this release's URLs
# (review of #219), and nothing has run. Each refused binary would leave a marker if it ran.
install_refusals() {
    local name output expected
    for name in tampered other-key older; do
        if output=$(run_install_commands "$name-$OLD"); then
            fail "the install commands accepted the $name release: $output"
        fi
        echo "$name: refused:"
        printf '%s\n' "$output"
        [[ $output != *"fleet-agent: OK"* ]] || fail "the $name release printed fleet-agent: OK"
        case $name in
            tampered) expected="fleet-agent: FAILED" ;;
            other-key) expected="Signature key id in fleet-agent.manifest.json.minisig is" ;;
            older) expected="no properly formatted checksum lines found" ;;
        esac
        [[ $output == *"$expected"* ]] || fail "the $name release was not refused with: $expected"
        vm_ok "test ! -e /tmp/refused-ran" || fail "the refused $name binary ran"
    done
    printf '%s' "a tampered binary, another key's manifest, and an older release refused, nothing run" > "$tmp/last-result"
}

# --- Setup --------------------------------------------------------------------------------------------

make_certs "$tmp" "$SERVER_NAME"
install_release "$OLD" "$dir/fleet-agent-$OLD" "$dir/test.key"
# The refused releases: a script that would leave a marker if it ran, changed after it was signed, and signed with
# another throwaway key.
mkscript "$tmp/refused.sh" "$OLD" "touch /tmp/refused-ran"
install_release "tampered-$OLD" "$tmp/refused.sh" "$dir/test.key"
printf '# changed after signing\n' >> "$stub/releases/tampered-$OLD/fleet-agent"
minisign -G -W -p "$tmp/other.pub" -s "$tmp/other.key" > /dev/null
install_release "other-key-$OLD" "$tmp/refused.sh" "$tmp/other.key"
install_release "older-$OLD" "$tmp/refused.sh" "$dir/test.key" 0.9.0
# The update releases this group's builds allow.
if [ -s "$dir/fleet-agent-$NEW" ]; then
    mkrelease "$stub/releases" good "$NEW" "$dir/fleet-agent-$NEW" "$dir/test.key"
fi
mkscript "$tmp/loops.sh" "$LOOPING" "echo \"vm-test: release $LOOPING started\" >&2; sleep 2; exit 1"
mkrelease "$stub/releases" crash_loop "$LOOPING" "$tmp/loops.sh" "$dir/test.key"
if [ -s "$dir/fleet-agent-$FAULTY" ] && [ -s "$dir/fleet-agent-$FIXED" ]; then
    mkrelease "$stub/releases" faulty "$FAULTY" "$dir/fleet-agent-$FAULTY" "$dir/test.key"
    mkrelease "$stub/releases" fixed "$FIXED" "$dir/fleet-agent-$FIXED" "$dir/test.key"
fi

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
put "$tmp/ca.pem" /tmp/ca.pem
put "$dir/test.pub" /tmp/release-key.pub
echo "vm-test: installing $OLD as the install page says"
vm "DEBIAN_FRONTEND=noninteractive $INSTALL_TOOLS > /dev/null"
check_output=$(run_install_commands "$OLD") || fail "the install commands refused release $OLD: $check_output"
expected_output="Signature and comment signature verified
Trusted comment: fleet-agent $OLD $UPDATE_TEST_TARGET release manifest
fleet-agent: OK"
[ "$check_output" = "$expected_output" ] || fail "the check printed '$check_output', expected '$expected_output'"
echo "vm-test: the check printed what the page says:"
printf '%s\n' "$check_output"
vm "cd /root/install-$OLD && chmod +x fleet-agent && printf '%s\n' '$ENROLL_TOKEN' | ./fleet-agent install --server https://$SERVER_NAME:$PORT --ca-file fleet-server-ca.pem --token-stdin"
# Shorter intervals than production, so the test takes minutes: a heartbeat every 10 s and a minute to
# confirm an update.
vm "printf '%s\n' '' 'update_confirm_seconds = 60' '' '[heartbeat]' 'interval_seconds = 10' 'min_seconds = 10' 'max_seconds = 60' \
    >> /etc/fleet-agent/config.toml && $LIB/current/fleet-agent check-config > /dev/null && systemctl restart fleet-agent"
config_sum=$(vm 'sha256sum /etc/fleet-agent/config.toml')
# Files with content must keep it; empty ones (the task ledger and its lock with no task yet, P3-A02)
# must still be there.
state_files=$(vm "cd $STATE && find . -maxdepth 1 -type f -size +0 ! -name 'update*' -printf '%f '")
empty_state_files=$(vm "cd $STATE && find . -maxdepth 1 -type f -empty ! -name 'update*' -printf '%f '")
echo "vm-test: installed; state files: $state_files; empty: $empty_state_files"
# The units this branch's installer writes, which every build here carries (#232).
UNIT_DIR=/etc/systemd/system
units_sum=$(vm "cd $UNIT_DIR && sha256sum fleet-agent.service fleet-agent-rollback.service fleet-agent-recovery.service")

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

# heartbeat_units VERSION true|false: an acknowledged heartbeat from VERSION since $since whose units.recovery is that.
heartbeat_units() {
    event_exists "[.[] | select(.kind == \"heartbeat\" and .agent_version == \"$1\" and .status == 200 and .at > $since and .units.recovery == $2)] | length > 0"
}

# #232: an agent whose units are from before recovery mode gets this release's units from a confirmed update, without
# another restart, and its heartbeats then say recovery mode is set up.
units_refreshed() {
    rollout=$1
    reset
    vm "sed -i -e 's/^OnFailure=fleet-agent-rollback.service fleet-agent-recovery.service\$/OnFailure=fleet-agent-rollback.service/' \
            -e '/^RestartMode=direct\$/d' $UNIT_DIR/fleet-agent.service
        rm -f $UNIT_DIR/fleet-agent-recovery.service
        systemctl daemon-reload && systemctl restart fleet-agent"
    vm_ok "! systemctl show -p OnFailure --value fleet-agent | grep -q fleet-agent-recovery" || fail "the old units still name the recovery unit"
    since=$(date +%s.%N)
    wait_until "a heartbeat from $OLD saying recovery mode is not set up" 90 heartbeat_units "$OLD" false
    local cursor starts
    cursor=$(vm "journalctl -n 1 --show-cursor --no-pager -o cat | sed -n 's/^-- cursor: //p'")
    [ -n "$cursor" ] || fail "cannot read the journal's cursor"
    offer good "$NEW"
    expect_result succeeded "$NEW"
    [ "$(cat "$tmp/last-result")" = succeeded ] || fail "the result has a note: $(cat "$tmp/last-result")"
    expect_one_version "$NEW" "$OLD"
    [ "$(vm "cd $UNIT_DIR && sha256sum fleet-agent.service fleet-agent-rollback.service fleet-agent-recovery.service")" = "$units_sum" ] \
        || fail "the units are not the new version's after the update"
    vm_ok "systemctl show -p OnFailure --value fleet-agent | grep -q fleet-agent-recovery" || fail "systemd was not reloaded after the refresh"
    vm "journalctl --after-cursor='$cursor' -u fleet-agent-update --no-pager -o cat" | grep -q "refreshed the systemd units from the new version" \
        || fail "the supervisor did not log the refresh"
    # The supervisor's restart into the new version is the only start: the refresh restarts nothing.
    starts=$(vm "journalctl --after-cursor='$cursor' -u fleet-agent --no-pager -o cat" | grep -c "^Started fleet-agent.service" || true)
    [ "$starts" = 1 ] || fail "fleet-agent.service was started $starts times during the update, expected once"
    since=$(date +%s.%N)
    wait_until "a heartbeat from $NEW saying recovery mode is set up" 90 heartbeat_units "$NEW" true
    echo "the confirmed update wrote $NEW's units and reloaded systemd; one start; heartbeats say recovery mode is set up"
    printf '%s' "succeeded: units refreshed, units.recovery true" > "$tmp/last-result"
}

# heartbeat_in_mode VERSION recovery|normal: an acknowledged heartbeat from VERSION since $since, in that mode.
heartbeat_in_mode() {
    local test='.recovery != null'
    [ "$2" = recovery ] || test='.recovery == null'
    event_exists "[.[] | select(.kind == \"heartbeat\" and .agent_version == \"$1\" and .status == 200 and .at > $since and $test)] | length > 0"
}
inventory_since() {
    event_exists "[.[] | select(.kind == \"inventory\" and .agent_version == \"$1\" and .status == 200 and .at > $since)] | length > 0"
}
task_poll_from() {
    event_exists "[.[] | select(.kind == \"task_poll\" and .agent_version == \"$1\" and .status == 200 and .at > $since)] | length > 0"
}

# #180, ADR 0030: a confirmed version that crash-loops, with nothing to roll back to, goes to recovery mode
# instead of stopping for good, and a fixed release reaches it through the signed update path.
recovery_mode() {
    rollout=$1
    reset
    # Tasks on, as the package scenarios set them (in "all" they already have, #288): apply_package_updates
    # enabled and a poll every 10 s, so normal mode polls and the check below that recovery mode does not
    # can fail.
    if ! vm_ok "grep -qx '\[tasks\]' /etc/fleet-agent/config.toml"; then
        vm "printf '%s\n' '' '[tasks]' 'enabled = [\"apply_package_updates\"]' '' '[task_poll]' 'interval_seconds = 10' 'min_seconds = 5' \
            >> /etc/fleet-agent/config.toml && $LIB/current/fleet-agent check-config > /dev/null \
            && systemctl reset-failed fleet-agent && systemctl restart fleet-agent"
    fi
    # A task in the ledger: refresh_reports is not enabled here, so it is refused (and recorded, nothing
    # run). The ledger with it and the [tasks] config must come through recovery mode and the fixed release.
    task_id=$(printf '00000000-0000-4000-8000-%012d' "$1")
    rm -f "$stub/task-result-$task_id.json"
    set_plan "$(jq -nc --arg id "$task_id" '{task: {id: $id, type: "refresh_reports", parameters: {}, timeout_seconds: 600, catalog_version: 1}}')"
    expect_task refused not_enabled_locally 120
    # The agent removes its copy of the result once the server has accepted it.
    wait_until "the agent to record the result as reported" 30 vm_ok "test ! -e $STATE/task-result.json"
    # What must stay unchanged is what is there now (in "all", with the package scenarios' task files too).
    config_sum=$(vm 'sha256sum /etc/fleet-agent/config.toml')
    state_files=$(vm "cd $STATE && find . -maxdepth 1 -type f -size +0 ! -name 'update*' ! -name '$MARKER' -printf '%f '")
    empty_state_files=$(vm "cd $STATE && find . -maxdepth 1 -type f -empty ! -name 'update*' -printf '%f '")
    [[ " $state_files " == *" task-ledger.jsonl "* ]] || fail "the task ledger is empty before the update: $state_files"
    vm_ok "grep -qx '\[tasks\]' /etc/fleet-agent/config.toml" || fail "the config has no [tasks] section"
    offer faulty "$FAULTY"
    expect_result succeeded "$FAULTY"
    expect_one_version "$FAULTY" "$OLD"
    # Positive control for the no-poll check below: in normal mode, this build polls for tasks.
    since=$(date +%s.%N)
    wait_until "a task poll from $FAULTY in normal mode" 60 task_poll_from "$FAULTY"
    echo "$FAULTY is installed and confirmed, and polls for tasks; now host state makes its normal mode fail at every start"
    since=$(date +%s.%N)
    # Everything the journal says from here on is this scenario's (the guest's clock is not the runner's).
    local cursor
    cursor=$(vm "journalctl -n 1 --show-cursor --no-pager -o cat | sed -n 's/^-- cursor: //p'")
    [ -n "$cursor" ] || fail "cannot read the journal's cursor"
    # reset-failed also resets the start counter, so the update's own start does not count towards the limit:
    # the crash loop is exactly StartLimitBurst=4 failed starts.
    vm "touch $STATE/$POISON && chmod 0600 $STATE/$POISON && systemctl reset-failed fleet-agent && systemctl restart fleet-agent"
    local end=$((SECONDS + 240 * slow))
    until heartbeat_in_mode "$FAULTY" recovery; do
        if ((SECONDS >= end)); then
            # In the job log, not only the artifact: what systemd and the units did.
            vm "systemctl show -p ActiveState -p SubState -p Result -p NRestarts fleet-agent fleet-agent-recovery fleet-agent-rollback
                journalctl -b --no-pager -o short-iso -u fleet-agent -u fleet-agent-rollback -u fleet-agent-recovery | grep -v 'DEBUG' | tail -n 120" 2>&1 || true
            fail "gave up after $((240 * slow))s waiting for a heartbeat in recovery mode from $FAULTY"
        fi
        sleep 2
    done
    vm_ok 'systemctl is-active --quiet fleet-agent-recovery' || fail "heartbeats in recovery mode, but fleet-agent-recovery.service is not active"
    vm_ok '! systemctl is-active --quiet fleet-agent' || fail "fleet-agent.service is active beside recovery mode"
    # Only this scenario's journal (after the cursor). With RestartMode=direct, OnFailure= starts the recovery
    # unit once, after systemd's start limit has ended the restarts: four failed starts, then the limit, then
    # recovery mode, in that order (review of #222).
    local panics journal limit_at recovery_at starts
    journal=$(vm "journalctl --after-cursor='$cursor' -u fleet-agent -u fleet-agent-recovery --no-pager -o cat")
    # The panic hook's own line: recovery mode's start line repeats the panic in its reason.
    panics=$(grep -c "panicked at src/vm_fault.rs" <<< "$journal" || true)
    starts=$(grep -c "Starting fleet-agent-recovery.service" <<< "$journal" || true)
    limit_at=$(grep -n -m1 "Start request repeated too quickly" <<< "$journal" | cut -d: -f1)
    recovery_at=$(grep -n -m1 "fleet-agent started in recovery mode" <<< "$journal" | cut -d: -f1)
    [ "$panics" -eq 4 ] || fail "$panics failed starts before recovery mode, expected StartLimitBurst=4"
    [ -n "$limit_at" ] || fail "systemd's start limit is not in the journal"
    [ -n "$recovery_at" ] || fail "recovery mode's start is not in the journal"
    [ "$limit_at" -lt "$recovery_at" ] || fail "recovery mode went on (line $recovery_at) before the start limit (line $limit_at)"
    [ "$starts" -eq 1 ] || fail "the recovery unit was started $starts times in the crash loop, expected once"
    ! grep -q "recovery mode is not needed" <<< "$journal" || fail "the recovery unit was started while systemd still restarted the service"
    echo "fleet-agent.service failed $panics times, then hit its start limit; recovery mode was started once, after it"
    local reason pid caps exe entered
    reason=$(jq -rs '[.[] | select(.kind == "heartbeat" and .recovery != null)] | last | .recovery.reason' "$events")
    entered=$(jq -rs '[.[] | select(.kind == "heartbeat" and .recovery != null)] | last | .recovery.entered_at' "$events")
    echo "recovery mode since $entered: $reason"
    [[ $reason == *"panicked"*"vm-test fault"* ]] || fail "the reason does not say what failed: $reason"
    pid=$(vm 'systemctl show -p MainPID --value fleet-agent-recovery')
    exe=$(vm "readlink /proc/$pid/exe")
    [ "$exe" = "$LIB/versions/$FAULTY/fleet-agent" ] || fail "recovery mode runs $exe, expected version $FAULTY"
    caps=$(vm "awk '/^CapBnd:/ { print \$2 }' /proc/$pid/status")
    [ "$caps" = 0000000000000000 ] || fail "recovery mode has capabilities (CapBnd $caps)"
    # Two more heartbeat intervals: recovery mode sends no report and polls for no task (the normal-mode starts
    # before it, which may have, are before this).
    since=$(date +%s.%N)
    sleep $((25 * slow))
    event_exists "[.[] | select((.kind == \"inventory\" or .kind == \"packages\" or .kind == \"task_poll\") and .at > $since and .agent_version == \"$FAULTY\")] | length == 0" \
        || fail "recovery mode sent a report or polled for a task"
    echo "recovery mode heartbeats as $FAULTY with no capabilities, and sends nothing else; now the server offers $FIXED"
    rollout=$(($1 + 1000))
    local offered
    offered=$(date +%s.%N)
    offer fixed "$FIXED"
    expect_result succeeded "$FIXED"
    # One version runs (recovery mode, `current/fleet-agent run --recovery`, would be a second process).
    expect_one_version "$FIXED" "$FAULTY"
    since=$(date +%s.%N)
    wait_until "a heartbeat in normal mode from $FIXED" 90 heartbeat_in_mode "$FIXED" normal
    # The cause is still there; the fixed release runs normally with it, reports included.
    vm_ok "test -e $STATE/$POISON" || fail "the poison file is gone"
    since=$(date +%s.%N)
    wait_until "a task poll from $FIXED" 60 task_poll_from "$FIXED"
    # Its startup report may come before the checks above end (a random splay of up to 60 s): count from
    # the offer.
    since=$offered
    wait_until "an inventory report from $FIXED" 150 inventory_since "$FIXED"
    vm "rm -f $STATE/$POISON"
    echo "recovery mode installed $FIXED, which confirmed and runs normally; recovery mode has stopped"
    printf '%s' "recovered: $FAULTY crash-looped, recovery mode installed $FIXED" > "$tmp/last-result"
}

# AC-2.3: the package report equals the installed packages of `dpkg-query --show` on the VM (status
# installed; removed config-files packages are left out, and interrupted installations are named in
# `skipped`, not listed): no package missing or invented, the same versions, and each source package,
# read here from the raw Source field (its version cut off, the package's own name when there is none).
package_report_matches_dpkg() {
    reset
    # Nothing installs or removes a package between the report and the listing it is compared with.
    vm 'systemctl stop apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service'
    rm -f "$stub/packages.json"
    # A first start (no inventory record), so the startup reports are not held back by the restart splay (#200).
    vm "systemctl stop fleet-agent && rm -f $STATE/inventory.json && systemctl start fleet-agent"
    wait_until "the startup package report" 90 test -s "$stub/packages.json"
    jq -e '.manager == "dpkg" and .unsupported_reason == null and .warnings == []' "$stub/packages.json" > /dev/null \
        || fail "the report is not a clean dpkg listing: $(jq -c '{manager, unsupported_reason, warnings}' "$stub/packages.json")"
    event_exists '[.[] | select(.kind == "packages" and .encoding == "gzip")] | length > 0' \
        || fail "the package report was not sent gzip-compressed"
    local format reference reported count interrupted skipped
    # shellcheck disable=SC2016 # dpkg-query's own field syntax, expanded by dpkg-query in the guest
    format='${db:Status-Abbrev}|${Package}:${Architecture} ${Version}|${Package}|${Source}\n'
    reference=$(vm "dpkg-query --show --showformat='$format'" \
        | awk -F'|' 'substr($1, 2, 1) ~ /[iWt]/ { s = $4; sub(/ .*/, "", s); if (s == "") s = $3; print $2 " " s }' | sort)
    # The second letter of the abbreviation: i installed, W triggers-awaited, t triggers-pending (all
    # installed and configured); H half-installed, U unpacked, F half-configured (interrupted, skipped).
    interrupted=$(vm "dpkg-query --show --showformat='$format'" \
        | awk -F'|' 'substr($1, 2, 1) ~ /[HUF]/ { print $3 }' | sort -u)
    skipped=$(jq -r '(.skipped // [])[].name' "$stub/packages.json" | sort -u)
    reported=$(jq -r '.packages[] | "\(.name):\(.architecture) \(.version) \(.source)"' "$stub/packages.json" | sort)
    count=$(printf '%s\n' "$reported" | grep -c .)
    [ "$count" -gt 100 ] || fail "only $count packages reported"
    if [ "$reference" != "$reported" ]; then
        diff <(printf '%s\n' "$reference") <(printf '%s\n' "$reported") | head -n 20 >&2 || true
        fail "the package report differs from dpkg-query on the VM (< dpkg-query, > report)"
    fi
    if [ "$interrupted" != "$skipped" ]; then
        diff <(printf '%s\n' "$interrupted") <(printf '%s\n' "$skipped") | head -n 20 >&2 || true
        fail "the skipped packages differ from the interrupted installations on the VM (< dpkg-query, > report)"
    fi
    echo "the package report lists the same $count packages as dpkg-query, with their source packages ($(printf '%s\n' "$skipped" | grep -c .) skipped)"
    agent_limits "startup reports, $count packages"
    printf '%s' "$count packages, equal to dpkg-query" > "$tmp/last-result"
}

# --- What is in use (FR-2.6, VT-APPLICABILITY) ------------------------------------------------------

SCAN_DROPIN=/etc/systemd/system/fleet-agent-library-scan.service.d

# fresh_reports: restarts the agent as on a first start (no inventory record, so no startup splay, #200),
# and sets $since for the reports that follow.
fresh_reports() {
    since=$(date +%s.%N)
    # reset-failed: these restarts would otherwise reach the unit's start limit (4 in 5 minutes).
    vm "systemctl stop fleet-agent && rm -f $STATE/inventory.json && systemctl reset-failed fleet-agent && systemctl start fleet-agent"
}
# Puts the VM back as the other scenarios expect it (the configuration unchanged), however the scenario ends.
in_use_cleanup() {
    vm "systemctl stop fvt-lo fvt-lan fvt-uselib fvt-chroot fvt-ct fvt-sock.socket fvt-sock.service 2>/dev/null; systemctl reset-failed fvt-lo fvt-lan fvt-uselib fvt-chroot fvt-ct 2>/dev/null
        rm -f /etc/systemd/system/fvt-sock.socket /etc/systemd/system/fvt-sock.service
        dpkg --purge fvt-listen-lo fvt-listen-lan fvt-listen-sock fvt-lib fvt-uselib fvt-idlelib fvt-idle fvt-netlib fvt-lolib fvt-chrootlib fvt-ctlib > /dev/null 2>&1
        rm -rf /var/lib/fvt-chroot /srv/fvt-ct
        rm -rf $SCAN_DROPIN $STATE/library-scan.json /run/reboot-required /run/reboot-required.pkgs; systemctl daemon-reload
        sed -i '/^\[packages\]$/,\$d' /etc/fleet-agent/config.toml; sed -i -e :a -e '/^\n*\$/{\$d;N;ba' -e '}' /etc/fleet-agent/config.toml
        systemctl reset-failed fleet-agent; systemctl restart fleet-agent" || true
}
packages_since() { event_exists "[.[] | select(.kind == \"packages\" and .status == 200 and .at > $since)] | length > 0"; }
inventory_since_now() { event_exists "[.[] | select(.kind == \"inventory\" and .status == 200 and .at > $since)] | length > 0"; }
in_use() { jq -c "${1:-.in_use}" "$stub/packages.json"; }
no_ptrace_in_the_agent() {
    local caps
    caps=$(vm 'systemctl show -p CapabilityBoundingSet --value fleet-agent')
    [ "$caps" = cap_dac_read_search ] || fail "fleet-agent.service has the capabilities '$caps', not cap_dac_read_search alone"
}

# VT-A01 and VT-A02 on the real image, under the real unit: services listening on loopback and on the
# VM's LAN address, and sshd on every address, named by package and class; the reboot flag null when
# Debian's file is missing and true when it is there; no process id, address, or port in the report;
# the agent's unit unchanged, without CAP_SYS_PTRACE. Then the library scan, enabled in the local
# config: only its transient unit carries CAP_SYS_PTRACE, with no network; the libraries processes that
# hold a listening socket map are named with the socket's class, one no process maps is not listed, and
# one upgraded under a running program is stale.
in_use_reported() {
    reset
    trap in_use_cleanup EXIT
    local p='bash /tmp/vm-test-packages.sh' lan props
    put "$here/vm-test-packages.sh" /tmp/vm-test-packages.sh
    vm "$p build fvt-listen-lo 1.0 && $p build fvt-listen-lan 1.0 && $p build fvt-listen-sock 1.0 && $p build fvt-lib 1.0 && $p build fvt-lib 1.1
        $p build fvt-uselib 1.0 && $p build fvt-idlelib 1.0 && $p build fvt-idle 1.0 && $p build fvt-netlib 1.0 && $p build fvt-lolib 1.0 && $p build fvt-chrootlib 1.0 && $p build fvt-ctlib 1.0
        dpkg -i /srv/fvt/debs/fvt-listen-lo_1.0_all.deb /srv/fvt/debs/fvt-listen-lan_1.0_all.deb /srv/fvt/debs/fvt-listen-sock_1.0_all.deb \
            /srv/fvt/debs/fvt-lib_1.0_all.deb /srv/fvt/debs/fvt-netlib_1.0_all.deb /srv/fvt/debs/fvt-lolib_1.0_all.deb \
            /srv/fvt/debs/fvt-chrootlib_1.0_all.deb /srv/fvt/debs/fvt-ctlib_1.0_all.deb \
            /srv/fvt/debs/fvt-uselib_1.0_all.deb /srv/fvt/debs/fvt-idlelib_1.0_all.deb /srv/fvt/debs/fvt-idle_1.0_all.deb > /dev/null"
    lan=$(vm "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -n 1")
    [ -n "$lan" ] || fail "the VM has no LAN address"
    vm "systemd-run --quiet --unit=fvt-lo /usr/libexec/fvt-listen-lo 127.0.0.1 18080 /usr/lib/fvt/libfvt-lolib.so.1
        systemd-run --quiet --unit=fvt-lan /usr/libexec/fvt-listen-lan $lan 18081 /usr/lib/fvt/libfvt-netlib.so.1
        mkdir -p /var/lib/fvt-chroot /srv/fvt-ct
        systemd-run --quiet --unit=fvt-chroot --setenv=FVT_CHROOT=/var/lib/fvt-chroot /usr/libexec/fvt-listen-lo 127.0.0.1 18084 /usr/lib/fvt/libfvt-chrootlib.so.1
        systemd-run --quiet --unit=fvt-ct unshare --mount --propagation private /bin/sh -c 'mount -t tmpfs fvt-ct /srv/fvt-ct && mkdir /srv/fvt-ct/usr /srv/fvt-ct/etc /srv/fvt-ct/old && mount --rbind /usr /srv/fvt-ct/usr && mount --rbind /etc /srv/fvt-ct/etc && for d in bin sbin lib lib64; do ln -s usr/\$d /srv/fvt-ct/\$d; done && cd /srv/fvt-ct && pivot_root . old && exec /usr/bin/python3 /usr/libexec/fvt-listen-lo 127.0.0.1 18085 /usr/lib/fvt/libfvt-ctlib.so.1'
        systemd-run --quiet --unit=fvt-uselib /usr/libexec/fvt-uselib /usr/lib/fvt/libfvt-lib.so.1
        printf '%s\n' '[Socket]' 'ListenStream=127.0.0.1:18082' > /etc/systemd/system/fvt-sock.socket
        printf '%s\n' '[Service]' 'ExecStart=/usr/libexec/fvt-listen-sock 127.0.0.1 18083' > /etc/systemd/system/fvt-sock.service
        systemctl daemon-reload && systemctl start fvt-sock.socket
        rm -f /run/reboot-required /run/reboot-required.pkgs"
    wait_until "the test services to listen" 30 vm_ok "ss -Hltn 'sport = :18080' | grep -q . && ss -Hltn 'sport = :18081' | grep -q . && ss -Hltn 'sport = :18082' | grep -q . && ss -Hltn 'sport = :18084' | grep -q . && ss -Hltn 'sport = :18085' | grep -q ."

    fresh_reports
    wait_until "a package report" 120 packages_since
    wait_until "an inventory report" 60 inventory_since_now
    echo "in_use: $(in_use)"
    in_use '.in_use.listening' | jq -e 'index({"package": "fvt-listen-lo", "class": "loopback"})' > /dev/null \
        || fail "fvt-listen-lo (127.0.0.1 only) is not loopback: $(in_use .in_use.listening)"
    in_use '.in_use.listening' | jq -e 'index({"package": "fvt-listen-lan", "class": "network"})' > /dev/null \
        || fail "fvt-listen-lan (on $lan) is not network: $(in_use .in_use.listening)"
    in_use '.in_use.listening' | jq -e 'index({"package": "fvt-listen-sock", "class": "loopback"})' > /dev/null \
        || fail "the socket-activated fvt-sock.service (systemd holds 127.0.0.1:18082) is not named: $(in_use .in_use.listening); the socket: $(vm "ss -Hltn --cgroup 'sport = :18082'"); systemd: $(vm 'systemctl list-sockets --all --show-types --full --no-legend --no-pager | grep 18082')"
    in_use '.in_use.listening' | jq -e 'index({"package": "openssh-server", "class": "network"})' > /dev/null \
        || fail "openssh-server is not network: $(in_use .in_use.listening)"
    in_use '.in_use.services' | jq -e 'index("fvt-uselib") and index("fvt-listen-lo")' > /dev/null \
        || fail "the running services' packages are missing: $(in_use .in_use.services)"
    in_use '.in_use | .library_scan == "off" and .complete == false and .libraries == null' | grep -qx true \
        || fail "the library scan is not off: $(in_use)"
    jq -e '[.warnings[] | select(.field == "in_use")] == []' "$stub/packages.json" > /dev/null \
        || fail "in_use warnings: $(jq -c .warnings "$stub/packages.json")"
    for leak in "$lan" 127.0.0.1 18080 18081 18082 '"pid' argv; do
        ! in_use | grep -qF -- "$leak" || fail "the in_use report contains '$leak'"
    done
    jq -e 'has("reboot_required") and .reboot_required == null and .reboot_required_packages == null' "$stub/inventory.json" > /dev/null \
        || fail "without /run/reboot-required the flag is not null: $(jq -c '{reboot_required, reboot_required_packages}' "$stub/inventory.json")"
    jq -e '.kernel_build | type == "string"' "$stub/inventory.json" > /dev/null || fail "no kernel_build"
    no_ptrace_in_the_agent
    [ "$(vm 'sha256sum /etc/systemd/system/fleet-agent.service' | cut -d' ' -f1)" = "$(sha256sum "$here/../src/install/fleet-agent.service" | cut -d' ' -f1)" ] \
        || fail "the installed fleet-agent.service is not the unit in the repository"
    ! vm_ok "journalctl -q --no-pager -o cat -u fleet-agent-library-scan | grep -q ." || fail "the library scan ran while it is off"

    vm 'printf "*** System restart required ***\n" > /run/reboot-required && printf "libc6\n" > /run/reboot-required.pkgs'
    fresh_reports
    wait_until "an inventory report with the reboot flag" 60 inventory_since_now
    jq -e '.reboot_required == true and .reboot_required_packages == ["libc6"]' "$stub/inventory.json" > /dev/null \
        || fail "with /run/reboot-required the flag is not true with libc6: $(jq -c '{reboot_required, reboot_required_packages}' "$stub/inventory.json")"
    vm 'rm -f /run/reboot-required /run/reboot-required.pkgs'

    # The scan, on. A drop-in holds it for a few seconds first, so its properties can be read while it runs.
    vm "printf '%s\n' '' '[packages]' 'library_scan = true' >> /etc/fleet-agent/config.toml && $LIB/current/fleet-agent check-config > /dev/null
        mkdir -p $SCAN_DROPIN && printf '%s\n' '[Service]' 'ExecStartPre=/bin/sleep 8' > $SCAN_DROPIN/hold.conf && systemctl daemon-reload"
    fresh_reports
    wait_until "the library scan unit to start" 120 vm_ok "systemctl is-active --quiet fleet-agent-library-scan || systemctl show -p ActiveState --value fleet-agent-library-scan | grep -q activating"
    props=$(vm 'systemctl show -p CapabilityBoundingSet -p PrivateNetwork -p IPAddressDeny -p ProtectSystem -p ProtectHome -p ProcSubset -p NoNewPrivileges fleet-agent-library-scan')
    echo "the scan unit while it runs: $(printf '%s' "$props" | tr '\n' ' ')"
    printf '%s\n' "$props" | grep -qx 'CapabilityBoundingSet=cap_sys_ptrace' || fail "the scan unit's capabilities: $props"
    printf '%s\n' "$props" | grep -qx 'ProtectHome=yes' || fail "the scan unit can read home directories: $props"
    printf '%s\n' "$props" | grep -qx 'ProcSubset=pid' || fail "the scan unit sees all of /proc: $props"
    printf '%s\n' "$props" | grep -qx 'PrivateNetwork=yes' || fail "the scan unit has a network: $props"
    printf '%s\n' "$props" | grep -qx 'ProtectSystem=strict' || fail "the scan unit can write the system: $props"
    no_ptrace_in_the_agent
    wait_until "a package report after the scan" 120 packages_since
    in_use '.in_use | .library_scan == "ran" and .complete == true' | grep -qx true \
        || fail "the scan did not run: $(in_use) $(jq -c .warnings "$stub/packages.json")"
    echo "timing and size: $(vm "journalctl -q --no-pager -o cat -u fleet-agent | grep 'read what is in use' | tail -n 2 | tr '\n' ' '"); packages $(jq '.packages | length' "$stub/packages.json")"
    in_use '.in_use.libraries' | jq -e 'index({"package": "fvt-lib", "stale": false})' > /dev/null \
        || fail "fvt-lib, mapped by a running program, is not listed: $(in_use .in_use.libraries)"
    in_use '.in_use.libraries' | jq -e '[.[] | select(.package == "fvt-idlelib")] == []' > /dev/null \
        || fail "fvt-idlelib, which no running process maps, is listed"
    # Positive evidence only (owner decision 2026-11-21): what processes holding a listening socket map.
    in_use '.in_use.loaded_by_listeners' | jq -e --arg lan "$lan:18081/tcp" 'any(.[]; (.packages | index("fvt-netlib")) and .class == "network" and .service == "fvt-lan.service" and .sockets == [$lan]) and any(.[]; (.packages | index("fvt-lolib")) and .class == "loopback" and .service == "fvt-lo.service" and .sockets == ["127.0.0.1:18080/tcp"])' > /dev/null \
        || fail "the libraries the listening test services map are not named with their class, unit, and socket: $(in_use .in_use.loaded_by_listeners | head -c 600)"
    in_use '.in_use.loaded_by_listeners' | jq -e 'any(.[]; .listener == "openssh-server" and .class == "network" and (.service | test("^ssh")) and any(.sockets[]; endswith(":22/tcp")) and (.packages | index("openssh-server")) and (.packages | index("libc6")))' > /dev/null \
        || fail "sshd and the libc it maps are not named as loaded by a network listener on port 22: $(in_use .in_use.loaded_by_listeners | head -c 600)"
    # A chroot'd listener (as haproxy's workers and postfix's smtpd are) maps host files and counts; a
    # container's listener (its own root filesystem, here a pivot_root'd tmpfs) is skipped.
    in_use '.in_use.loaded_by_listeners' | jq -e 'any(.[]; (.packages | index("fvt-chrootlib")) and .service == "fvt-chroot.service" and .sockets == ["127.0.0.1:18084/tcp"])' > /dev/null \
        || fail "the chroot'd listener's library is not named: $(in_use .in_use.loaded_by_listeners | head -c 600); its root: $(vm "readlink /proc/\$(systemctl show -p MainPID --value fvt-chroot)/root")"
    in_use '.in_use.loaded_by_listeners' | jq -e 'all(.[]; (.packages | index("fvt-ctlib") | not) and .service != "fvt-ct.service")' > /dev/null \
        || fail "the container's listener is named: $(in_use .in_use.loaded_by_listeners | head -c 600)"
    in_use '.in_use.loaded_by_listeners' | jq -e 'all(.[]; (.packages | index("fvt-lib") | not) and (.packages | index("fvt-idlelib") | not))' > /dev/null \
        || fail "a library no listening process maps is named as loaded by a listener: $(in_use .in_use.loaded_by_listeners | head -c 600)"
    in_use '.in_use.scanned_at | type == "string"' | grep -qx true || fail "no scanned_at"
    echo "CPU: the agent since its start, the scan unit's run included in the elapsed time above: $(vm 'systemctl show -p CPUUsageNSec --value fleet-agent') ns"

    # Asked for again within the hour (the heartbeat's report_request): the last scan is reused, not run again.
    local first_scan scans
    first_scan=$(in_use '.in_use.scanned_at')
    scans=$(vm "journalctl -q --no-pager -o cat -u fleet-agent-library-scan | grep -c '^Started fleet-agent-library-scan' || true")
    [ "$scans" -ge 1 ] || fail "the journal shows no run of the scan unit"
    since=$(date +%s.%N)
    set_plan '{"report_request": ["packages"]}'
    wait_until "a package report on request" 120 packages_since
    set_plan '{}'
    [ "$(in_use '.in_use.scanned_at')" = "$first_scan" ] || fail "a report on request ran the scan again: $(in_use '.in_use.scanned_at'), first $first_scan"
    [ "$(vm "journalctl -q --no-pager -o cat -u fleet-agent-library-scan | grep -c '^Started fleet-agent-library-scan' || true")" = "$scans" ] \
        || fail "the scan unit ran again within the hour"
    vm_ok '! systemctl is-active --quiet fleet-agent-library-scan' || fail "the scan unit is still running"

    # Kept in the state directory (owner decision 2026-11-20, S4): private to the agent, and reused after
    # the agent restarts, without a new scan.
    [ "$(vm "stat -c '%a %U' $STATE/library-scan.json")" = "600 root" ] \
        || fail "the scan's record is not private to the agent: $(vm "stat -c '%a %U' $STATE/library-scan.json")"
    fresh_reports
    wait_until "a package report after the agent restarted" 120 packages_since
    [ "$(in_use '.in_use.scanned_at')" = "$first_scan" ] || fail "a restart ran the scan again: $(in_use '.in_use.scanned_at'), first $first_scan"
    [ "$(vm "journalctl -q --no-pager -o cat -u fleet-agent-library-scan | grep -c '^Started fleet-agent-library-scan' || true")" = "$scans" ] \
        || fail "the scan unit ran again after the restart, within the hour"

    # Upgraded under the running program, which still maps the old file: stale. The record is removed
    # (test scaffolding) so the restarted agent scans again now rather than in an hour.
    vm "rm -rf $SCAN_DROPIN $STATE/library-scan.json && systemctl daemon-reload && dpkg -i /srv/fvt/debs/fvt-lib_1.1_all.deb > /dev/null"
    fresh_reports
    wait_until "a package report after the upgrade" 120 packages_since
    in_use '.in_use.libraries' | jq -e 'index({"package": "fvt-lib", "stale": true})' > /dev/null \
        || fail "fvt-lib, upgraded under a running program, is not stale: $(in_use .in_use.libraries)"

    in_use_cleanup
    trap - EXIT
    [ "$(vm 'sha256sum /etc/fleet-agent/config.toml')" = "$config_sum" ] || fail "the configuration was not put back"
    echo "listening: loopback and network named by package, sshd network; reboot flag null then true; the scan unit alone had CAP_SYS_PTRACE and no network; libraries loaded by listeners, unmapped, and stale"
    agent_limits "in-use reports and the library scan"
    printf '%s' "loopback, network, reboot null/true, scan unit only with ptrace, loaded by listeners, stale library" > "$tmp/last-result"
}

# --- apply_package_updates (P3-AGENT-UPDATES) ---------------------------------------------------------

task_id=
# run_task SCENARIO_ID TIMEOUT_SECONDS: the stub offers one new apply_package_updates task with that
# deadline (each scenario runs in a subshell, so its id names the task).
run_task() {
    task_id=$(printf '00000000-0000-4000-8000-%012d' "$1")
    shift
    rm -f "$stub/task-result-$task_id.json"
    set_plan "$(jq -nc --arg id "$task_id" --argjson timeout "$1" \
        '{task: {id: $id, type: "apply_package_updates", parameters: {}, timeout_seconds: $timeout, catalog_version: 1}}')"
}
task_result() { cat "$stub/task-result-$task_id.json"; }
task_done() { test -s "$stub/task-result-$task_id.json"; }
# expect_task OUTCOME [REASON] [SECONDS]: waits for the result and checks its outcome and reason.
expect_task() {
    local outcome reason
    wait_until "the result of task $task_id" "${3:-300}" task_done
    set_plan '{}'
    outcome=$(task_result | jq -r .outcome)
    reason=$(task_result | jq -r '.reason // ""')
    echo "task $task_id: $outcome${reason:+ ($reason)}; details $(task_result | jq -c .details)"
    printf '%s' "$outcome${reason:+: $reason}" > "$tmp/last-result"
    if [ "$outcome" != "$1" ] || [ "$reason" != "${2:-}" ]; then
        task_result | jq -r .output | tail -n 40 >&2
        fail "the task ended $outcome${reason:+ ($reason)}, expected $1${2:+ ($2)}"
    fi
}
output_has() {
    task_result | jq -r .output | grep -qF -- "$1" || { task_result | jq -r .output | tail -n 40 >&2; fail "the task output lacks: $1"; }
}
version_of() { vm "dpkg-query -W -f '\${Version}' $1" 2> /dev/null; }
no_task_units() {
    [ -z "$(vm "systemctl list-units --all --plain --no-legend 'fleet-agent-task-*' | awk '{print \$1}'")" ]
}

updates_setup() {
    vm 'systemctl stop apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service 2>/dev/null || true'
    # needrestart from Debian, before Debian's sources are set aside.
    vm 'DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get -q update > /dev/null && DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get -q install -y --no-install-recommends needrestart > /dev/null'
    vm 'mkdir -p /root/vm-test-sources && find /etc/apt/sources.list.d -maxdepth 1 -type f -exec mv {} /root/vm-test-sources/ \; ;
        [ ! -s /etc/apt/sources.list ] || mv /etc/apt/sources.list /root/vm-test-sources/sources.list
        echo "deb [trusted=yes] file:/srv/fvt/repo ./" > /etc/apt/sources.list.d/fvt.list'
    put "$here/vm-test-packages.sh" /tmp/vm-test-packages.sh
    local p='bash /tmp/vm-test-packages.sh'
    vm "$p build fvt-demo 1.0 && $p build fvt-demo 1.1 'touch /run/reboot-required'
        $p build fvt-held 1.0 && $p build fvt-held 1.1
        $p build fvt-victim 1.0 && $p build fvt-rm 1.0 && $p build fvt-rm 1.1 '' 'Conflicts: fvt-victim'
        $p build fvt-slow 1.0 && $p build fvt-slow 1.1 'sleep 45'
        $p build fvt-hang 1.0 && $p build fvt-hang 1.1 'sleep 900'
        dpkg -i /srv/fvt/debs/fvt-demo_1.0_all.deb /srv/fvt/debs/fvt-held_1.0_all.deb \
            /srv/fvt/debs/fvt-slow_1.0_all.deb /srv/fvt/debs/fvt-hang_1.0_all.deb \
            /srv/fvt/debs/fvt-victim_1.0_all.deb /srv/fvt/debs/fvt-rm_1.0_all.deb > /dev/null
        apt-mark hold fvt-held > /dev/null
        rm -f /run/reboot-required
        systemd-run --quiet --unit=fvt-demo /usr/libexec/fvt-demo infinity"
    # The owner's opt-in (DEC-14), and polls often enough for a test.
    vm "printf '%s\n' '' '[tasks]' 'enabled = [\"apply_package_updates\"]' '' '[task_poll]' 'interval_seconds = 10' 'min_seconds = 5' \
        >> /etc/fleet-agent/config.toml && $LIB/current/fleet-agent check-config > /dev/null && systemctl restart fleet-agent"
    since=$(date +%s.%N)
    wait_until "a heartbeat after enabling the task" 90 event_exists "[.[] | select(.kind == \"heartbeat\" and .status == 200 and .at > $since)] | length > 0"
    jq -e '.tasks.supported | index("apply_package_updates")' "$stub/heartbeat.json" > /dev/null \
        || fail "the agent does not report apply_package_updates as supported: $(jq -c .tasks "$stub/heartbeat.json")"
    jq -e '.tasks.enabled | index("apply_package_updates")' "$stub/heartbeat.json" > /dev/null \
        || fail "the agent does not report apply_package_updates as enabled: $(jq -c .tasks "$stub/heartbeat.json")"
}

package_report_since() {
    event_exists "[.[] | select(.kind == \"packages\" and .status == 200 and .at > $1)] | length > 0" \
        && jq -e --arg v "$2" '[.packages[] | select(.name == "fvt-demo" and .version == $v)] | length == 1' "$stub/packages.json" > /dev/null
}

packages_upgraded() {
    updates_setup
    # fvt-rm 1.1 conflicts with the installed fvt-victim: its upgrade would need a removal, so it is
    # kept back, and reported held back.
    vm 'bash /tmp/vm-test-packages.sh publish fvt-demo_1.1_all.deb fvt-held_1.1_all.deb fvt-rm_1.1_all.deb'
    local boot invocation started
    boot=$(boot_id)
    invocation=$(vm 'systemctl show -p InvocationID --value fvt-demo')
    # The task asks for the package report as soon as the upgrade has ended, before its last steps, so
    # the report may arrive before the result: it is looked for from the task's start.
    started=$(date +%s.%N)
    run_task "$1" 3600
    expect_task succeeded
    [ "$(version_of fvt-demo)" = 1.1 ] || fail "fvt-demo is $(version_of fvt-demo), expected 1.1"
    [ "$(version_of fvt-held)" = 1.0 ] || fail "the held fvt-held was upgraded to $(version_of fvt-held)"
    task_result | jq -e '.details.reboot_required == true' > /dev/null || fail "reboot_required is not true"
    task_result | jq -e '.details.packages_upgraded == 1' > /dev/null || fail "packages_upgraded is not 1"
    [ "$(version_of fvt-rm)" = 1.0 ] || fail "fvt-rm was upgraded, removing fvt-victim"
    vm_ok 'dpkg-query -W fvt-victim' || fail "fvt-victim was removed"
    if ! task_result | jq -e '.details.packages_held_back == ["fvt-held", "fvt-rm"]' > /dev/null; then
        task_result | jq -r .output | sed -n '/--simulate/,/needrestart -b/p' >&2
        fail "packages_held_back is not [fvt-held, fvt-rm]"
    fi
    task_result | jq -e '.details.services_needing_restart | index("fvt-demo.service")' > /dev/null \
        || fail "needrestart did not name fvt-demo.service: $(task_result | jq -c .details.services_needing_restart)"
    output_has '$ /usr/bin/apt-get -q --error-on=any -o DPkg::Lock::Timeout=300 update'
    output_has 'Unpacking fvt-demo (1.1) over (1.0)'
    output_has '$ /usr/sbin/needrestart -b -r l'
    output_has '1 package upgraded: fvt-demo'
    output_has 'the task never reboots'
    [ "$(boot_id)" = "$boot" ] || fail "the VM rebooted"
    [ "$(vm 'systemctl show -p InvocationID --value fvt-demo')" = "$invocation" ] || fail "fvt-demo.service was restarted"
    no_task_units || fail "a task unit is left: $(vm "systemctl list-units --all --plain --no-legend 'fleet-agent-task-*'")"
    wait_until "a package report with fvt-demo 1.1" 120 package_report_since "$started" 1.1
    vm 'rm -f /run/reboot-required'
    echo "fvt-demo 1.0 -> 1.1, fvt-held and fvt-rm held back, reboot required and not done, fvt-demo.service named and not restarted, package report sent"
    agent_limits "apply_package_updates and its package report"
    printf '%s' "succeeded: 1 upgraded, 2 held back, reboot_required" > "$tmp/last-result"
}

lock_contention() {
    # A release waits 300 s for the lock, then fails. The fault build (the packages group) waits what
    # $LOCK_WAIT_FILE says, read when the agent starts (#288).
    local wait=300 started took
    if [ "$old_is_fault_build" = 1 ]; then
        wait=$LOCK_WAIT_TEST
        since=$(date +%s.%N)
        # reset-failed: this restart would otherwise count towards the unit's start limit (4 in 5 minutes).
        vm "printf '%s\n' $wait > $STATE/$LOCK_WAIT_FILE && chmod 0600 $STATE/$LOCK_WAIT_FILE \
            && systemctl reset-failed fleet-agent && systemctl restart fleet-agent"
        wait_until "a heartbeat from $OLD after the restart" 90 heartbeat_from "$OLD"
    fi
    vm 'bash /tmp/vm-test-packages.sh publish fvt-slow_1.1_all.deb'
    vm "systemd-run --quiet --unit=fvt-locker python3 -c 'import fcntl, os, time
fd = os.open(\"/var/lib/dpkg/lock-frontend\", os.O_RDWR | os.O_CREAT, 0o640)
fcntl.lockf(fd, fcntl.LOCK_EX)
time.sleep(1800)'"
    sleep 2
    started=$SECONDS
    run_task "$1" 3600
    expect_task failed lock_timeout $((wait + 180))
    took=$((SECONDS - started))
    # The agent read no later start's file: the next scenario restarts it with the default again.
    vm "rm -f $STATE/$LOCK_WAIT_FILE"
    vm 'systemctl stop fvt-locker'
    ((took >= wait)) || fail "the task failed after ${took}s, before its ${wait}s wait for the lock ended"
    echo "lock_timeout after ${took}s, waiting ${wait}s for the lock"
    [ "$(version_of fvt-slow)" = 1.0 ] || fail "fvt-slow was upgraded although the lock was held"
    output_has "another program holds /var/lib/dpkg/lock-frontend; waiting up to $wait seconds for it"
    output_has "held /var/lib/dpkg/lock-frontend for $wait seconds"
    output_has 'the package manager is busy'
    no_task_units || fail "a task unit is left"
    task_result | jq -e '.output | test("\\$ /usr/bin/apt-get") | not' > /dev/null || fail "apt-get ran although the lock was held"
}

agent_restart_mid_upgrade() {
    vm 'bash /tmp/vm-test-packages.sh publish fvt-slow_1.1_all.deb'
    run_task "$1" 3600
    wait_until "the upgrade's unit to run" 180 vm_ok "systemctl is-active --quiet fleet-agent-task-$task_id-2.service"
    sleep 3
    vm 'systemctl restart fleet-agent'
    vm_ok "systemctl is-active --quiet fleet-agent-task-$task_id-2.service" || fail "the upgrade stopped with the agent"
    expect_task succeeded "" 300
    [ "$(version_of fvt-slow)" = 1.1 ] || fail "fvt-slow is $(version_of fvt-slow), expected 1.1"
    output_has 'the upgrade finished while the agent was restarting'
    no_task_units || fail "a task unit is left"
}

forced_timeout() {
    vm 'bash /tmp/vm-test-packages.sh publish fvt-hang_1.1_all.deb'
    run_task "$1" 60
    expect_task timed_out "" 300
    output_has 'dpkg --configure -a'
    output_has 'ran past its deadline of 60 seconds'
    vm_ok '! pgrep -f "^sleep 900"' || fail "the hanging maintainer script outlived the task: $(vm 'pgrep -af "sleep 900"')"
    no_task_units || fail "a task unit is left"
    local status
    status=$(vm "dpkg-query -W -f '\${db:Status-Abbrev}' fvt-hang")
    [ "$status" != "ii " ] || fail "fvt-hang is fully installed: the upgrade was not stopped"
    echo "stopped at the deadline; fvt-hang left as '$status', as the repair guidance says"
    agent_limits "an upgrade stopped at its deadline"
}

# --- Memory and task limits (#182) -------------------------------------------------------------------

# agent_limits LABEL: the service's peaks so far (since its last start) and its limit events; fails if the
# agent reached MemoryMax or TasksMax (or a MemoryHigh, if a drop-in sets one). The peaks are kept for scenario 374.
agent_limits() {
    local seen event count
    # shellcheck disable=SC2016 # expanded in the guest
    seen=$(vm 'cg=/sys/fs/cgroup$(systemctl show fleet-agent -p ControlGroup --value)
echo "memory.peak $(cat "$cg/memory.peak" 2> /dev/null || echo unknown)"
echo "pids.peak $(cat "$cg/pids.peak" 2> /dev/null || echo unknown)"
sed "s/^/memory.events./" "$cg/memory.events"
sed "s/^/pids.events./" "$cg/pids.events"')
    echo "limits, $1: $(printf '%s\n' "$seen" | tr '\n' ' ')"
    printf '%s: %s\n' "$1" "$(printf '%s\n' "$seen" | grep -E '^(memory|pids)\.peak ' | tr '\n' ' ' | sed 's/ $//')" \
        >> "$tmp/limits-peaks"
    for event in memory.events.high memory.events.max memory.events.oom_kill pids.events.max; do
        count=$(printf '%s\n' "$seen" | awk -v e="$event" '$1 == e { print $2 }')
        [ "${count:-0}" = 0 ] || fail "$1: the agent reached a limit ($event $count)"
    done
}

within_limits() {
    local want shown
    want=$(unit_limits "$here/../src/install/fleet-agent.service")
    for unit in fleet-agent fleet-agent-recovery; do
        shown=$(vm "systemctl show $unit -p MemoryHigh -p MemoryMax -p MemorySwapMax -p OOMPolicy -p TasksMax" \
            | sort | tr '\n' ' ' | sed 's/ $//')
        [ "$shown" = "$want" ] || fail "$unit has '$shown', the unit file says '$want'"
    done
    # No OOM kill of the agent in any scenario the journal still holds (this boot at least).
    if vm "journalctl -u fleet-agent --no-pager -o cat | grep -q oom-kill"; then
        fail "the agent was killed for memory: $(vm 'journalctl -u fleet-agent --no-pager -o short-iso | grep -B2 oom-kill | tail -n 6')"
    fi
    agent_limits "now"
    cat "$tmp/limits-peaks"
    printf '%s' "limits applied ($want); never reached; peaks: $(tr '\n' ';' < "$tmp/limits-peaks" | sed 's/;$//')" > "$tmp/last-result"
}


# --- Running and recording (vm-test-record.sh) -------------------------------------------------------

diagnostics() {
    echo "--- layout and state"
    vm "ls -l $LIB $LIB/versions $STATE; cat $STATE/update.json 2>/dev/null" 2>&1 || echo "(the VM does not answer)"
    echo "--- journals (this boot and the one before)"
    for b in -1 0; do
        vm "journalctl -b $b --no-pager -o short-iso -u fleet-agent -u fleet-agent-update -u fleet-agent-rollback -u fleet-agent-recovery | tail -n 80" 2>&1 || true
    done
    echo "--- task units"
    vm "systemctl list-units --all --plain --no-legend 'fleet-agent-task-*'; journalctl --no-pager -o cat -u 'fleet-agent-task-*' | tail -n 60" 2>&1 || true
    echo "--- what the stub saw (last 30)"
    tail -n 30 "$events"
}

os="Debian 13"
record_header() {
    echo "## Agent update failure tests on a VM (P1-A12): $group"
    echo
    echo "Scenario group \`$group\` (scripts/vm-test.sh; each group has a VM of its own)."
    echo "$os under QEMU ($accel), image $(basename "$image"); agent $OLD updated to $NEW (and $LOOPING, a crash-looping release); installed with the install page's commands (curl and minisign, the signature checked with the release key, then \`fleet-agent install\`)."
    echo "The package report check (AC-2.3) compares the agent's startup package report with \`dpkg-query --show\` on the VM."
    echo "The package update scenarios (P3-AGENT-UPDATES) run the real apply_package_updates task against a local repository of test packages built in the guest."
    echo "The units scenario (#232) starts from units older than recovery mode and checks that the confirmed update writes the new version's."
    echo "The limits scenario (#182) checks the installed unit's memory and task limits are applied, and that no scenario in this VM brought the agent to them; it lists the peaks the scenarios measured."
    echo "The recovery mode scenario (#180, ADR 0030) makes a confirmed $FAULTY (the VM fault build) crash-loop and checks that recovery mode installs $FIXED."
    echo "Each update scenario ends by checking that exactly one working version runs (links, installed versions, the service's binary, one agent process, no supervisor or update record left, an acknowledged heartbeat), that the configuration and credential are unchanged, and that a state record holds exactly what it should: kept after a confirmed update, restored by a rollback."
}

# in_group GROUP...: whether this run's group is one of GROUP, or all.
in_group() { [ "$group" = all ] || [[ " $* " == *" $group "* ]]; }

if in_group install; then
    scenario 290 "First install refuses a tampered binary, another key, and an older release (#181)" install_refusals
    scenario 300 "Package report matches dpkg-query (AC-2.3)" package_report_matches_dpkg
    scenario 309 "What is in use: listening services, the reboot flag, the library scan (VT-APPLICABILITY)" in_use_reported
fi
if in_group updates-a; then
    scenario 301 "Supervisor killed before the switch" kill_before_switch
    scenario 302 "Supervisor killed after the switch" kill_after_switch
    scenario 303 "Hard reset after the switch, before confirmation" reset_after_switch
    scenario 304 "Reboot after confirmation" reboot_after_confirmation
fi
if in_group updates-b; then
    scenario 305 "Reboot before the switch" reboot_before_switch
    scenario 306 "Crash-looping release across a reboot" crash_loop_and_reboot
    scenario 308 "Confirmed update refreshes the units (#232)" units_refreshed
fi
if in_group packages; then
    scenario 370 "Package updates applied, no reboot (AC-3.4, AC-3.5)" packages_upgraded
    scenario 371 "Package manager lock held: lock_timeout" lock_contention
    scenario 372 "Agent restarted during the upgrade (L8)" agent_restart_mid_upgrade
    scenario 373 "Forced timeout ends the process tree" forced_timeout
fi
# In "all", after the package scenarios as before; in a group, last, for what ran in its VM.
[ "$group" != all ] || scenario 374 "The agent stays inside its memory and task limits (#182)" within_limits
if in_group recovery; then
    scenario 307 "Crash loop on a confirmed version: recovery mode (#180)" recovery_mode
fi
[ "$group" = all ] || scenario 374 "The agent stays inside its memory and task limits (#182)" within_limits

# shellcheck disable=SC2016 # expanded in the guest
os=$(vm '. /etc/os-release; echo "$PRETTY_NAME"' 2> /dev/null || echo "Debian 13")
# The EXIT trap writes results.xml and results.md.
[ "$record_failed" = 0 ]
