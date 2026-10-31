#!/bin/sh
# Runs the agent binary under the sandbox of its systemd unit, on a host running systemd, and checks the
# sandbox costs no fact (P1-PACKAGING, review of #72). Agent CI runs it on every agent change with the
# musl release binary, the binary that ships:
#
#   sudo scripts/sandbox-smoke.sh BINARY [UNIT]      (run from agent/; UNIT defaults to the installer's)
#
# 1. A local HTTPS stand-in for the agent API (scripts/sandbox-stub.py) and a throwaway certificate.
# 2. The binary runs twice as a transient systemd service: once with every [Service] option of UNIT except
#    how it starts and restarts (so the test cannot drift from the unit), once with none of them.
# 3. Both must have a heartbeat accepted and write heartbeat.json and inventory.json in their state
#    directory, and the sandboxed inventory must have every fact the unsandboxed one has and no warning
#    it does not. A blocked system call (SystemCallErrorNumber=EPERM) or a hidden path would otherwise
#    only show as a quietly missing fact across the fleet.
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
    for name in sandboxed baseline; do
        systemctl stop "fleet-agent-smoke-$name" 2>/dev/null || true
        systemctl reset-failed "fleet-agent-smoke-$name" 2>/dev/null || true
        rm -rf "/var/lib/fleet-agent-smoke-$name" "/etc/fleet-agent-smoke-$name"
    done
    [ -z "$pids" ] || kill $pids 2>/dev/null || true
    rm -rf "$tmp" /usr/local/lib/fleet-agent-smoke
}
trap cleanup EXIT

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
    | grep -Ev '^(ExecStart|Type|Restart|RestartSec|RestartPreventExitStatus|StateDirectory)=')
[ -n "$properties" ] || { echo "sandbox-smoke: no [Service] options in $unit" >&2; exit 1; }

port=8443
for name in sandboxed baseline; do
    mkdir -p "$tmp/$name"
    python3 "$here/sandbox-stub.py" "$port" "$tmp/cert.pem" "$tmp/key.pem" "$tmp/$name" &
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
    set -- --unit="fleet-agent-smoke-$name" --property="StateDirectory=fleet-agent-smoke-$name"
    if [ "$name" = sandboxed ]; then
        # One property per line of the unit; values with spaces are kept whole.
        while IFS= read -r line; do set -- "$@" --property="$line"; done <<EOF
$properties
EOF
    fi
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
        && [ -s /var/lib/fleet-agent-smoke-sandboxed/heartbeat.json ] \
        && [ -s /var/lib/fleet-agent-smoke-sandboxed/inventory.json ] \
        && [ -s /var/lib/fleet-agent-smoke-baseline/heartbeat.json ]; then
        ok=1
        break
    fi
    sleep 1
done
for name in sandboxed baseline; do
    echo "--- journal: fleet-agent-smoke-$name"
    journalctl -u "fleet-agent-smoke-$name" --no-pager -o cat | tail -n 40
done
if [ -z "$ok" ]; then
    echo "sandbox-smoke: the agent did not report and record its state within 60 seconds" >&2
    for name in sandboxed baseline; do
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
EOF
if ! result=$(python3 "$tmp/compare.py" "$tmp/sandboxed/inventory.json" "$tmp/baseline/inventory.json" 2>&1); then
    printf '%s\n' "$result" >&2
    annotate "sandbox-smoke: the sandbox cost facts" "$result
$(journal sandboxed)"
    exit 1
fi
printf '%s\n' "$result"
