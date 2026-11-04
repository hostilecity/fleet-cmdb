#!/bin/bash
# Checks scripts/vm-test-record.sh without a VM (P1-A12): a scenario that passes, one that fails with a
# reason, and one that dies on an unwrapped error (exit 255, as SSH does) are all recorded, the later
# scenarios still run, and results.xml and results.md are written. Run by the Agent VM tests workflow
# before the VM boots:
#
#   scripts/vm-test-record-selftest.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=vm-test-record.sh
. "$here/vm-test-record.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
record_out=$work/out
record_tmp=$work/tmp
mkdir -p "$record_out/logs" "$record_tmp"

diagnostics() { echo "diagnostics were collected"; }
record_header() { echo "## self-test"; }
check() {
    if ! eval "$1"; then
        echo "vm-test-record self-test: FAILED: $2" >&2
        exit 1
    fi
}

passes() { printf 'succeeded' > "$record_tmp/last-result"; }
fails_with_a_reason() { fail "current is versions/1.0.1, expected versions/1.0.0"; }
dies_like_ssh() {
    echo "ssh: connect to host 127.0.0.1 port 2222: Connection refused" >&2
    (exit 255)
    echo "not reached"
}
after_the_failures() { :; }

scenario 1 "passes" passes > /dev/null
scenario 2 "fails with a reason" fails_with_a_reason > /dev/null
scenario 3 "dies like ssh" dies_like_ssh > /dev/null
scenario 4 "runs after the failures" after_the_failures > /dev/null
record_write 1

xml=$record_out/results.xml
md=$record_out/results.md
check '[ -s "$xml" ] && [ -s "$md" ]' "results.xml and results.md were not written"
check 'grep -q "tests=\"4\" failures=\"2\"" "$xml"' "results.xml does not count 4 tests and 2 failures: $(head -n 3 "$xml")"
check 'grep -q "failure message=\"current is versions/1.0.1, expected versions/1.0.0\"" "$xml"' "the reason given to fail is not the failure message"
check 'grep -q "failure message=\"scenario exited 255 without a FAILED line" "$xml"' "a scenario that died with 255 is not recorded with its exit status"
check '! grep -q "not reached" "$record_out/logs/dies_like_ssh.log"' "the dying scenario went on after the error"
check 'grep -q "diagnostics were collected" "$record_out/logs/dies_like_ssh.log"' "no diagnostics in the log of a failed scenario"
check 'grep -q "| runs after the failures | passed |" "$md"' "the scenario after the failures did not run"
check 'grep -q "| passes | passed | succeeded |" "$md"' "the update result of a passing scenario is not in results.md"
check '! grep -q "setup" "$xml"' "a setup failure was recorded although scenarios ran"

# A script that fails during the setup still writes results, with the reason.
record_passed=0 record_failed=0 record_cases= record_rows= record_written=
rm -f "$xml" "$md"
( fail "gave up after 300s waiting for SSH on the first boot" ) 2> /dev/null || true
record_write 1
check 'grep -q "name=\"setup\"" "$xml" && grep -q "SSH on the first boot" "$xml"' "a failure during the setup is not recorded"

echo "vm-test-record self-test: OK"
