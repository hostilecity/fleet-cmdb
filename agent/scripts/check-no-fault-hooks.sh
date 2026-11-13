#!/bin/sh
# The release binary contains no fault-injection code (P3-X03 AC, threat model S7), as CI runs it:
#
#   scripts/check-no-fault-hooks.sh RELEASE_BINARY TEST_BINARY   (run from agent/)
#
# The hooks that stop the agent at a kill point (src/tasks/poller/tests.rs `crash_at`) or fail a
# ledger append (src/tasks/ledger/tests.rs `fail_point`) live in `#[cfg(test)]` modules, and every
# call to them in other code is behind `#[cfg(test)]`, so a build without `cfg(test)` cannot compile
# them in. This checks that three ways:
#
# 1. Source: each line of non-test code that calls `tests::crash_at(` or `tests::fail_point(` comes
#    straight after a `#[cfg(test)]` line, and Cargo.toml declares no `[features]` that could switch
#    hooks on in another build.
# 2. Positive control: the unit-test binary contains FAULT_HOOK_MARKER (src/test_support.rs), which
#    every hook keeps, so the binary check below would see a hook if one were there.
# 3. The release binary does not contain it.
#
# Exits 1 and says why when the check fails, and 2 when a binary cannot be read or scanned.
set -eu

release=${1:?usage: check-no-fault-hooks.sh RELEASE_BINARY TEST_BINARY}
test_bin=${2:?usage: check-no-fault-hooks.sh RELEASE_BINARY TEST_BINARY}
marker=$(sed -n 's/^pub const FAULT_HOOK_MARKER: &str = "\(.*\)";$/\1/p' src/test_support.rs)
[ -n "$marker" ] || { echo "check-no-fault-hooks: FAULT_HOOK_MARKER not found in src/test_support.rs" >&2; exit 1; }

status=0
fail() {
    echo "check-no-fault-hooks: $1" >&2
    status=1
}

# 1. Every hook call outside the test modules is behind #[cfg(test)].
calls=$(grep -rn --include='*.rs' -E 'tests::(crash_at|fail_point)\(' src | grep -v '/tests\.rs:' || true)
[ -n "$calls" ] || fail "no hook calls found in src: has the check gone stale?"
printf '%s\n' "$calls" | while IFS=: read -r file line _; do
    [ -n "$file" ] || continue
    above=$(sed -n "$((line - 1))p" "$file" | tr -d ' ')
    if [ "$above" != "#[cfg(test)]" ]; then
        echo "check-no-fault-hooks: $file:$line calls a fault hook without #[cfg(test)] on the line above" >&2
        exit 1
    fi
done || status=1
if grep -q '^\[features\]' Cargo.toml; then
    fail "Cargo.toml declares [features]; a feature could compile fault hooks into a release"
fi

# Whether FILE contains the marker: 0 yes, 1 no. Anything else (a missing or unreadable file, a read
# error) stops the check, so an artefact that cannot be scanned never passes as one without hooks.
has_marker() {
    if [ ! -f "$1" ] || [ ! -r "$1" ]; then
        echo "check-no-fault-hooks: cannot read $1" >&2
        exit 2
    fi
    found=0
    grep -aqF "$marker" "$1" || found=$?
    case "$found" in
        0 | 1) return "$found" ;;
        *) echo "check-no-fault-hooks: grep failed on $1 (status $found)" >&2; exit 2 ;;
    esac
}

# 2. The unit-test binary has the marker.
has_marker "$test_bin" || fail "the unit-test binary $test_bin lacks the fault-hook marker, so this check cannot see hooks"

# 3. The release binary does not.
if has_marker "$release"; then
    fail "the release binary $release contains fault-injection code"
fi

if [ "$status" -eq 0 ]; then
    echo "check-no-fault-hooks: the hooks are test-only, the test binary has them, and $release does not"
fi
exit "$status"
