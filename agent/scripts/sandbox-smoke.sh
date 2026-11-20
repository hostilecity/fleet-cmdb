#!/bin/sh
# Runs the agent binary under the sandbox of its systemd unit, on a host running systemd, and checks the
# sandbox costs no fact (P1-PACKAGING, review of #72). Agent CI runs it on every agent change with the
# musl release binary, the binary that ships:
#
#   sudo scripts/sandbox-smoke.sh BINARY [UNIT]      (run from agent/; UNIT defaults to the installer's)
#
# 1. A local HTTPS stand-in for the agent API (scripts/update-stub.py, with no plan: it accepts every
#    heartbeat and inventory report) and a throwaway certificate.
# 2. The binary runs twice as a transient systemd service: once with every [Service] option of UNIT except
#    how it starts and restarts (so the test cannot drift from the unit), once with none of them.
# 3. Both must have a heartbeat accepted and write heartbeat.json and inventory.json in their state
#    directory, and the sandboxed inventory must have every fact the unsandboxed one has and no warning
#    it does not. A blocked system call (SystemCallErrorNumber=EPERM) or a hidden path would otherwise
#    only show as a quietly missing fact across the fleet.
# 4. Both send a package report (P2-AGENT-PACKAGES, gzip): the sandboxed one must list the same
#    packages as the unsandboxed one, with the same manager and no new warning, so `dpkg-query` works
#    under the unit (the runner is a dpkg system). Both report what is in use (FR-2.6, VT-A01), and the
#    sandboxed one names the same listening and running services' packages: no new privilege is needed.
# 5. The sandboxed agent opened its task ledger (P3-A02) in the state directory: an append-only file it
#    flushes with fsync, file and directory, before any task step returns, so the sandbox must allow both.
# 6. The unit's memory and task limits (#182) are in force on the sandboxed services: `systemctl show` and
#    the kernel's own files in their cgroups hold the values of UNIT.
# 7. A third run, "large", has the same options and a dpkg database of 20,000 installed packages (the most
#    a package report may list; scripts/dpkg-status-large.py) bound over /var/lib/dpkg. It must send all
#    20,000 without reaching MemoryMax or TasksMax; its peaks are printed, as the measurement the limits
#    rest on.
# 8. A fourth run, "oomchild", is "large" with MemoryMax=48M: dpkg-query (about 70 MiB) is the OOM victim,
#    not the agent. OOMPolicy=stop must stop the whole unit (result oom-kill); with `continue`, the agent
#    would carry on under the same pressure. Every run here starts under DefaultOOMPolicy=continue (a
#    system.conf.d drop-in, undone at the end), so it is the unit's own line that stops it, not the default.
set -eu

binary=${1:?usage: sudo scripts/sandbox-smoke.sh BINARY [UNIT]}
unit=${2:-src/install/fleet-agent.service}
here=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "sandbox-smoke: run as root (sudo)" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "sandbox-smoke: needs a host running systemd" >&2; exit 2; }

tmp=$(mktemp -d)
pids=

# In GitHub Actions, a failure is also reported as an annotation with the agent's journal, since that is
# what someone reading the run (or its API) sees first.
annotate() {
    [ -n "${GITHUB_ACTIONS:-}" ] || return 0
    body=$(printf '%s\n' "$2" | tail -n 60 | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')
    echo "::error title=$1::$body"
}
journal() { journalctl -u "fleet-agent-smoke-$1" --no-pager -o cat 2>&1 | tail -n 60; }
cleanup() {
    for name in sandboxed baseline large oomchild; do
        systemctl stop "fleet-agent-smoke-$name" 2>/dev/null || true
        systemctl reset-failed "fleet-agent-smoke-$name" 2>/dev/null || true
        rm -rf "/var/lib/fleet-agent-smoke-$name" "/etc/fleet-agent-smoke-$name"
    done
    # shellcheck disable=SC2086 # one word per process id
    [ -z "$pids" ] || kill $pids 2>/dev/null || true
    rm -rf "$tmp" /usr/local/lib/fleet-agent-smoke
    if [ -e "$oom_default" ]; then
        rm -f "$oom_default"
        systemctl daemon-reexec || true
    fi
}
oom_default=/etc/systemd/system.conf.d/90-fleet-agent-sandbox-smoke.conf
if [ -e "$oom_default" ]; then
    echo "sandbox-smoke: $oom_default exists; another run is in progress or was interrupted" >&2
    exit 2
fi
trap cleanup EXIT

# The opposite of the unit's OOMPolicy= as systemd's default, so the oomchild run (8) tests the unit's line.
mkdir -p "$(dirname "$oom_default")"
printf '[Manager]\nDefaultOOMPolicy=continue\n' > "$oom_default"
systemctl daemon-reexec
[ "$(systemctl show -p DefaultOOMPolicy --value)" = continue ] \
    || { echo "sandbox-smoke: could not set DefaultOOMPolicy=continue for the test" >&2; exit 1; }

# The binary outside the home directories, as installed (ProtectHome= makes /home read-only, not hidden).
install -D -m 0755 "$binary" /usr/local/lib/fleet-agent-smoke/fleet-agent

# A throwaway CA and a localhost server certificate it signs (the agent, rightly, refuses a self-signed
# CA certificate presented as the server's own).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=sandbox-smoke CA" \
    -keyout "$tmp/ca-key.pem" -out "$tmp/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
    -keyout "$tmp/key.pem" -out "$tmp/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$tmp/ext.cnf"
openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca-key.pem" -CAcreateserial -days 1 \
    -extfile "$tmp/ext.cnf" -out "$tmp/cert.pem" 2>/dev/null

# The unit's [Service] options, minus how the service starts and restarts.
properties=$(sed -n '/^\[Service\]/,/^\[/p' "$unit" | grep -E '^[A-Za-z]+=' \
    | grep -Ev '^(ExecStart|Type|Restart|RestartSec|RestartPreventExitStatus|StateDirectory|StateDirectoryMode)=')
[ -n "$properties" ] || { echo "sandbox-smoke: no [Service] options in $unit" >&2; exit 1; }

# The large host's dpkg database, made from this runner's own packages.
python3 -I "$here/dpkg-status-large.py" /var/lib/dpkg/status 20000 "$tmp/dpkg-large"

started=$(date +%s)
port=8443
for name in sandboxed baseline large oomchild; do
    mkdir -p "$tmp/$name"
    python3 "$here/update-stub.py" "$port" "$tmp/cert.pem" "$tmp/key.pem" "$tmp/$name" &
    pids="$pids $!"
    etc="/etc/fleet-agent-smoke-$name"
    install -d -m 0700 "$etc"
    install -m 0644 "$tmp/ca.pem" "$etc/ca.pem"
    umask 077
    cat > "$etc/config.toml" <<EOF
server_url = "https://localhost:$port"
credential = "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001"
ca_file = "$etc/ca.pem"
state_dir = "/var/lib/fleet-agent-smoke-$name"
log_level = "debug"
EOF
    umask 022
    # Both runs get a private state directory: the agent refuses a shared one, sandbox or not.
    set -- --unit="fleet-agent-smoke-$name" --property="StateDirectory=fleet-agent-smoke-$name" \
        --property=StateDirectoryMode=0700
    if [ "$name" != baseline ]; then
        # One property per line of the unit; values with spaces are kept whole.
        while IFS= read -r line; do set -- "$@" --property="$line"; done <<EOF
$properties
EOF
    fi
    case "$name" in
        large) set -- "$@" --property="BindReadOnlyPaths=$tmp/dpkg-large:/var/lib/dpkg" ;;
        # After the unit's own MemoryMax=, so this one applies.
        oomchild) set -- "$@" --property="BindReadOnlyPaths=$tmp/dpkg-large:/var/lib/dpkg" --property=MemoryMax=48M ;;
    esac
    sleep 1
    if ! out=$(systemd-run "$@" /usr/local/lib/fleet-agent-smoke/fleet-agent run --config "$etc/config.toml" 2>&1); then
        printf '%s\n' "$out" >&2
        annotate "sandbox-smoke: systemd-run refused the $name service" "$out"
        exit 1
    fi
    printf '%s\n' "$out"
    port=$((port + 1))
done

ok=
for _ in $(seq 1 60); do
    if [ -s "$tmp/sandboxed/inventory.json" ] && [ -s "$tmp/baseline/inventory.json" ] \
        && [ -s "$tmp/sandboxed/packages.json" ] && [ -s "$tmp/baseline/packages.json" ] \
        && [ -s /var/lib/fleet-agent-smoke-sandboxed/heartbeat.json ] \
        && [ -s /var/lib/fleet-agent-smoke-sandboxed/inventory.json ] \
        && [ -s /var/lib/fleet-agent-smoke-baseline/heartbeat.json ] \
        && [ -f /var/lib/fleet-agent-smoke-sandboxed/task-ledger.jsonl ] \
        && [ -s "$tmp/large/packages.json" ]; then
        ok=1
        break
    fi
    sleep 1
done
for name in sandboxed baseline large; do
    echo "--- journal: fleet-agent-smoke-$name"
    journalctl -u "fleet-agent-smoke-$name" --no-pager -o cat | tail -n 40
done
if [ -z "$ok" ]; then
    echo "sandbox-smoke: the agent did not report and record its state (and open its task ledger, and send the large host's packages) within 60 seconds" >&2
    for name in sandboxed baseline large; do
        annotate "sandbox-smoke: $name agent did not report within 60 s" \
            "$(systemctl status "fleet-agent-smoke-$name" --no-pager 2>&1 | head -n 5)
$(ls -l "/var/lib/fleet-agent-smoke-$name" "$tmp/$name" 2>&1)
$(journal "$name")"
    done
    exit 1
fi

cat > "$tmp/compare.py" <<'EOF'
import json, sys
sandboxed, baseline = (json.load(open(path)) for path in sys.argv[1:3])
envelope = {"schema_version", "agent_version", "report_id", "collected_at", "warnings"}
facts = sorted(set(baseline) - envelope)
lost = [f for f in facts if baseline[f] not in (None, []) and sandboxed.get(f) in (None, [])]
fewer = {f: (len(baseline[f]), len(sandboxed[f] or [])) for f in ("disks", "network_interfaces")
         if isinstance(baseline.get(f), list) and len(sandboxed.get(f) or []) < len(baseline[f])}
new = [w for w in sandboxed["warnings"] if w not in baseline["warnings"]]
print("facts present in both runs:", ", ".join(f for f in facts if sandboxed.get(f) not in (None, [])))
for name, value in (("facts lost in the sandbox", lost), ("list entries lost", fewer), ("warnings only in the sandbox", new)):
    if value:
        print(f"sandbox-smoke: {name}: {value}", file=sys.stderr)
if lost or fewer or new:
    sys.exit(1)
print("sandbox-smoke: the sandboxed agent reported every fact the unsandboxed one did, with no new warning")

# Package reports (P2-AGENT-PACKAGES).
sandboxed, baseline = (json.load(open(path)) for path in sys.argv[3:5])
key = lambda p: (p["name"], p["architecture"], p["version"], p["source"])
problems = []
if sandboxed["manager"] != baseline["manager"]:
    problems.append(f"manager {sandboxed['manager']!r} ({sandboxed['unsupported_reason']}), "
                    f"unsandboxed {baseline['manager']!r} ({baseline['unsupported_reason']})")
if baseline["manager"] != "dpkg":
    problems.append(f"the unsandboxed agent found no dpkg: {baseline['unsupported_reason']}")
missing = sorted(set(map(key, baseline["packages"])) - set(map(key, sandboxed["packages"])))
extra = sorted(set(map(key, sandboxed["packages"])) - set(map(key, baseline["packages"])))
new = [w for w in sandboxed["warnings"] if w not in baseline["warnings"]]
names = lambda report: sorted(s["name"] for s in report.get("skipped") or [])
if names(sandboxed) != names(baseline):
    problems.append(f"skipped packages {names(sandboxed)}, unsandboxed {names(baseline)}")
for name, value in (("packages missing in the sandbox", missing[:10]), ("packages only in the sandbox", extra[:10]),
                    ("package warnings only in the sandbox", new)):
    if value:
        problems.append(f"{name}: {value}")
for problem in problems:
    print(f"sandbox-smoke: {problem}", file=sys.stderr)
if problems:
    sys.exit(1)
print(f"sandbox-smoke: the sandboxed agent listed the same {len(sandboxed['packages'])} packages as the unsandboxed one")

# What is in use (FR-2.6, VT-A01): read under the unit as it is, with no new privilege, so the sandboxed
# agent must name the same listening and running services' packages as the unsandboxed one.
problems = []
for label, report in (("sandboxed", sandboxed), ("unsandboxed", baseline)):
    if report.get("in_use") is None:
        reasons = [w["message"] for w in report["warnings"] if w["field"] == "in_use"]
        problems.append(f"the {label} agent reported no in_use: {reasons}")
if not problems:
    for field in ("listening", "services"):
        if sandboxed["in_use"][field] != baseline["in_use"][field]:
            problems.append(f"in_use.{field} {sandboxed['in_use'][field]}, unsandboxed {baseline['in_use'][field]}")
for problem in problems:
    print(f"sandbox-smoke: {problem}", file=sys.stderr)
if problems:
    sys.exit(1)
print(f"sandbox-smoke: in use, read in the sandbox: listening {sandboxed['in_use']['listening']}, "
      f"{len(sandboxed['in_use']['services'])} services' packages, unnamed {sandboxed['in_use']['unnamed_listeners']}")
EOF
if ! result=$(python3 "$tmp/compare.py" "$tmp/sandboxed/inventory.json" "$tmp/baseline/inventory.json" \
    "$tmp/sandboxed/packages.json" "$tmp/baseline/packages.json" 2>&1); then
    printf '%s\n' "$result" >&2
    annotate "sandbox-smoke: the sandbox cost facts" "$result
$(journal sandboxed)"
    exit 1
fi
printf '%s\n' "$result"

# --- The memory and task limits (#182) -------------------------------------------------------------------

# bytes VALUE: a systemd size (128M, 1G, a plain number) in bytes, as `systemctl show` and the cgroup print it.
bytes() {
    case "$1" in
        *K) echo $((${1%K} * 1024)) ;;
        *M) echo $((${1%M} * 1024 * 1024)) ;;
        *G) echo $((${1%G} * 1024 * 1024 * 1024)) ;;
        *) echo "$1" ;;
    esac
}
value_in_unit() { printf '%s\n' "$properties" | sed -n "s/^$1=//p" | tail -n 1; }
limits_failed() {
    echo "sandbox-smoke: $1" >&2
    annotate "sandbox-smoke: the limits of $unit" "$1
$(journal "${2:-sandboxed}")"
    exit 1
}

memory_high=$(value_in_unit MemoryHigh)
[ -n "$memory_high" ] || memory_high=infinity
memory_max=$(value_in_unit MemoryMax)
swap_max=$(value_in_unit MemorySwapMax)
tasks_max=$(value_in_unit TasksMax)
oom_policy=$(value_in_unit OOMPolicy)
if [ -z "$memory_max" ] || [ -z "$swap_max" ] || [ -z "$tasks_max" ] || [ -z "$oom_policy" ]; then
    limits_failed "$unit does not set all of MemoryMax=, MemorySwapMax=, TasksMax=, and OOMPolicy="
fi
want="MemoryHigh=$(bytes "$memory_high") MemoryMax=$(bytes "$memory_max") MemorySwapMax=$(bytes "$swap_max") OOMPolicy=$oom_policy TasksMax=$tasks_max"
kernel_high=$(bytes "$memory_high")
[ "$kernel_high" != infinity ] || kernel_high=max
want_kernel="memory.high=$kernel_high memory.max=$(bytes "$memory_max") memory.swap.max=$(bytes "$swap_max") pids.max=$tasks_max"
for name in sandboxed large; do
    service="fleet-agent-smoke-$name"
    shown=$(systemctl show "$service" -p MemoryHigh -p MemoryMax -p MemorySwapMax -p OOMPolicy -p TasksMax \
        | sort | tr '\n' ' ' | sed 's/ $//')
    [ "$shown" = "$want" ] || limits_failed "$service: systemctl show gives '$shown', the unit says '$want'" "$name"
    # The kernel's own view: the service's cgroup enforces the same values.
    cgroup=/sys/fs/cgroup$(systemctl show "$service" -p ControlGroup --value)
    kernel="memory.high=$(cat "$cgroup/memory.high") memory.max=$(cat "$cgroup/memory.max") memory.swap.max=$(cat "$cgroup/memory.swap.max") pids.max=$(cat "$cgroup/pids.max")"
    [ "$kernel" = "$want_kernel" ] || limits_failed "$service: its cgroup holds '$kernel', not the unit's '$want_kernel'" "$name"
    echo "sandbox-smoke: $service runs with the unit's limits in force ($shown; $kernel)"
done

# The large host: every package sent, and no limit reached on the way.
count=$(python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["packages"]))' "$tmp/large/packages.json")
[ "$count" = 20000 ] || limits_failed "the large host's package report lists $count packages, not 20000" large
cgroup=/sys/fs/cgroup$(systemctl show fleet-agent-smoke-large -p ControlGroup --value)
events=$(tr '\n' ' ' < "$cgroup/memory.events")
peak=$(cat "$cgroup/memory.peak" 2> /dev/null || echo unknown)
tasks_peak=$(cat "$cgroup/pids.peak" 2> /dev/null || echo unknown)
echo "sandbox-smoke: 20,000-package report: memory peak $peak bytes (MemoryMax $(bytes "$memory_max")), tasks peak $tasks_peak (TasksMax $tasks_max); memory.events: $events"
for event in high max oom oom_kill; do
    n=$(sed -n "s/^$event //p" "$cgroup/memory.events")
    [ "${n:-0}" = 0 ] || limits_failed "the large host's agent reached a memory limit: memory.events $event $n ($events)" large
done
refused=$(sed -n 's/^max //p' "$cgroup/pids.events" 2> /dev/null)
[ "${refused:-0}" = 0 ] || limits_failed "the large host's agent reached TasksMax ($refused forks refused)" large
echo "sandbox-smoke: the limits are in force, and a 20,000-package host stays below them"

# OOMPolicy=stop when a child is the victim: the oomchild run's dpkg-query, not the agent.
waited=0
until state=$(systemctl show fleet-agent-smoke-oomchild -p ActiveState --value) \
    && { [ "$state" = failed ] || [ "$state" = inactive ]; }; do
    waited=$((waited + 1))
    [ "$waited" -le 90 ] || limits_failed "with MemoryMax=48M, the oomchild service is still $state after 90 s: OOMPolicy=stop did not stop it" oomchild
    sleep 1
done
result=$(systemctl show fleet-agent-smoke-oomchild -p Result --value)
victim=$(journalctl -k --since "@$started" --no-pager -o cat \
    | grep -F "oom_memcg=/system.slice/fleet-agent-smoke-oomchild.service" | sed -n 's/.*,task=\([^,]*\),.*/\1/p' | tail -n 1)
[ "$victim" = dpkg-query ] || limits_failed "the oomchild run's OOM victim was '${victim:-none}', not dpkg-query" oomchild
[ "$result" = oom-kill ] || limits_failed "the oomchild service ended with result $result, not oom-kill" oomchild
echo "sandbox-smoke: OOMPolicy=$oom_policy, under DefaultOOMPolicy=$(systemctl show -p DefaultOOMPolicy --value): the kernel killed the agent's dpkg-query, and systemd stopped the whole unit (result $result)"
