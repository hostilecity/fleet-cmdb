# shellcheck shell=bash
# Running and recording the scenarios of scripts/vm-test.sh (P1-A12): each scenario runs in a subshell,
# and every outcome is recorded, a failure with no "vm-test: FAILED" line (an SSH error, say) too.
# results.xml (JUnit) and results.md are written by record_write, which the caller also runs from its
# EXIT trap, so they exist however the script ends. Sourced, not run; scripts/vm-test-record-selftest.sh
# checks it without a VM.
#
# The caller sets record_out (the results directory) and record_tmp (a scratch directory), and defines
# `diagnostics` (printed into the log of a failed scenario) and `record_header` (the Markdown text above
# the table).

record_out=${record_out:-}
record_tmp=${record_tmp:-}
record_passed=0
record_failed=0
record_cases=
record_rows=
record_written=

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

# fail MESSAGE: ends the scenario (or, outside one, the script) with MESSAGE as the reason.
fail() {
    echo "vm-test: FAILED: $*" >&2
    printf '%s' "$*" > "$record_tmp/fail-message"
    exit 1
}

# record_case NAME SECONDS STATUS MESSAGE RESULT: one test case (STATUS 0 passed).
record_case() {
    local name=$1 took=$2 status=$3 message=$4 result=$5 escaped
    escaped=$(printf '%s' "$name" | xml_escape)
    if [ "$status" = 0 ]; then
        record_passed=$((record_passed + 1))
        record_cases+="  <testcase classname=\"agent-update-vm\" name=\"$escaped\" time=\"$took\"/>"$'\n'
        record_rows+="| $name | passed | $result | ${took}s |"$'\n'
    else
        record_failed=$((record_failed + 1))
        record_cases+="  <testcase classname=\"agent-update-vm\" name=\"$escaped\" time=\"$took\"><failure message=\"$(printf '%s' "$message" | xml_escape)\"/></testcase>"$'\n'
        record_rows+="| $name | **failed**: $message | $result | ${took}s |"$'\n'
        if [ -n "${GITHUB_ACTIONS:-}" ]; then
            echo "::error title=vm-test: $name::$message"
        fi
    fi
}

# scenario ID NAME FUNCTION: runs `FUNCTION ID` in a subshell, and records it.
scenario() {
    local id=$1 name=$2 fn=$3 start log status message result=""
    start=$SECONDS
    log=$record_out/logs/$fn.log
    rm -f "$record_tmp/last-result" "$record_tmp/fail-message"
    echo "== $name"
    set +e
    (
        set -e
        "$fn" "$id"
    ) 2>&1 | tee "$log"
    status=${PIPESTATUS[0]}
    set -e
    if [ -s "$record_tmp/last-result" ]; then
        result=$(cat "$record_tmp/last-result")
    fi
    message=
    if [ "$status" != 0 ]; then
        if [ -s "$record_tmp/fail-message" ]; then
            message=$(cat "$record_tmp/fail-message")
        else
            message="scenario exited $status without a FAILED line (see logs/$fn.log)"
        fi
        { diagnostics || true; } >> "$log" 2>&1
    fi
    record_case "$name" "$((SECONDS - start))" "$status" "$message" "$result"
}

# record_write: results.xml and results.md (once). A script that ends before every scenario ran, in the
# setup for example, gets a failed "setup" case with the reason.
record_write() {
    local exit_status=${1:-0}
    [ -z "$record_written" ] || return 0
    record_written=1
    if [ "$exit_status" != 0 ] && [ $((record_passed + record_failed)) = 0 ]; then
        local message="the script exited $exit_status before any scenario ran"
        if [ -s "$record_tmp/fail-message" ]; then
            message="$(cat "$record_tmp/fail-message") (exit $exit_status, before any scenario ran)"
        fi
        record_case "setup" 0 "$exit_status" "$message" ""
    fi
    mkdir -p "$record_out"
    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n'
        printf '<testsuite name="agent-update-vm" tests="%s" failures="%s" time="%s">\n' \
            "$((record_passed + record_failed))" "$record_failed" "$SECONDS"
        printf '%s' "$record_cases"
        printf '</testsuite>\n'
    } > "$record_out/results.xml"
    {
        { record_header || true; } 2> /dev/null
        echo
        echo "| Scenario | Outcome | Update result | Time |"
        echo "| --- | --- | --- | --- |"
        printf '%s' "$record_rows"
        echo
        echo "$record_passed passed, $record_failed failed, in ${SECONDS}s."
    } > "$record_out/results.md"
}
