#!/bin/sh
# Proves each task privilege works under the agent's real unit (P3-A05), on a host running systemd.
# Agent CI runs it after the sandbox smoke test:
#
#   sudo scripts/task-privilege-smoke.sh TEST_BINARY [UNIT]      (run from agent/; UNIT defaults to the
#                                                                 installer's)
#
# TEST_BINARY is the agent's unit-test binary (`cargo test --no-run`). Its `privilege_smoke_*` tests
# (src/tasks/executor/tests.rs, ignored in a plain `cargo test`) run as a transient systemd service with
# every [Service] option of UNIT, read from the file as scripts/sandbox-smoke.sh does, so the check cannot
# drift from the unit:
#
# - read_only: a task program runs as a child of the agent, inside the sandbox, with the fixed
#   environment, and cannot write /usr (ProtectSystem=strict);
# - service_manager: `systemctl restart` of a unit, from inside the sandbox, restarts it (a throwaway
#   fleet-agent-privsmoke-dummy.service started here);
# - package_manager: a program runs in a transient unit outside the sandbox, can write /usr, gets the
#   fixed environment, cannot read /etc/fleet-agent (InaccessiblePaths=), and is stopped at its deadline.
set -eu

binary=${1:?usage: sudo scripts/task-privilege-smoke.sh TEST_BINARY [UNIT]}
unit=${2:-src/install/fleet-agent.service}
[ "$(id -u)" = 0 ] || { echo "task-privilege-smoke: run as root (sudo)" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "task-privilege-smoke: needs a host running systemd" >&2; exit 2; }

created_etc=
cleanup() {
    systemctl stop fleet-agent-privsmoke-dummy.service fleet-agent-privsmoke.service 2>/dev/null || true
    systemctl reset-failed fleet-agent-privsmoke-dummy.service fleet-agent-privsmoke.service 2>/dev/null || true
    for id in a501 a502 a503; do
        name="fleet-agent-task-00000000-0000-4000-8000-00000000$id-1.service"
        systemctl stop "$name" 2>/dev/null || true
        systemctl reset-failed "$name" 2>/dev/null || true
    done
    rm -f /usr/local/lib/fleet-agent-privsmoke-unit /usr/local/lib/fleet-agent-privsmoke-direct \
        /usr/local/lib/fleet-agent-privsmoke-test
    if [ -n "$created_etc" ]; then rm -rf /etc/fleet-agent; else rm -f /etc/fleet-agent/privsmoke-probe; fi
}
trap cleanup EXIT

# The binary outside the home directories (ProtectHome= makes /home read-only, not hidden, but keep it
# where an installed agent would be).
install -D -m 0755 "$binary" /usr/local/lib/fleet-agent-privsmoke-test

# A secret the package manager unit must not be able to read.
if [ ! -d /etc/fleet-agent ]; then created_etc=1; install -d -m 0700 /etc/fleet-agent; fi
umask 077
echo privsmoke-secret > /etc/fleet-agent/privsmoke-probe
umask 022

# The unit restart_service-style tasks restart.
systemd-run --quiet --unit=fleet-agent-privsmoke-dummy --property=Type=exec /bin/sleep 3600

# The unit's [Service] options, minus how the service starts and restarts.
properties=$(sed -n '/^\[Service\]/,/^\[/p' "$unit" | grep -E '^[A-Za-z]+=' \
    | grep -Ev '^(ExecStart|Type|Restart|RestartSec|RestartPreventExitStatus|StateDirectory|StateDirectoryMode)=')
[ -n "$properties" ] || { echo "task-privilege-smoke: no [Service] options in $unit" >&2; exit 1; }
set -- --unit=fleet-agent-privsmoke --wait --pipe --quiet --property=StateDirectory=fleet-agent-privsmoke
while IFS= read -r line; do set -- "$@" --property="$line"; done <<EOF
$properties
EOF

status=0
systemd-run "$@" /usr/local/lib/fleet-agent-privsmoke-test --ignored --test-threads=1 privilege_smoke \
    || status=$?
if [ "$status" -ne 0 ]; then
    echo "--- journal: fleet-agent-privsmoke"
    journalctl -u fleet-agent-privsmoke --no-pager -o cat 2>&1 | tail -n 60
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error title=task-privilege-smoke::a task privilege does not work under $unit (see the log)"
    fi
    exit 1
fi
echo "task-privilege-smoke: read_only, service_manager, and package_manager all work under $unit"
