#!/bin/sh
# The no-shell check for the task module (P3-A03 AC, threat model section 8), as CI runs it:
#
#   scripts/check-task-spawns.sh [DIR]      (default: src/tasks, run from agent/)
#   scripts/check-task-spawns.sh --self-test (the check must catch the bypasses it is meant to catch)
#
# In the non-test code of DIR (files named tests.rs, and each `#[cfg(test)]` + `mod tests {` block up to
# its closing `}` in column 0, are left out; test code may run /bin/sh to build process trees):
#
# 1. `Command` (std::process), `.arg(`, `.args(`, `.envs(`, and `.env(` appear only in
#    executor/spawn.rs, the one place a task process is started, and `Command::new(` appears there
#    exactly once. Every argument therefore goes through its typed API: `&'static str`, a ValidatedArg
#    after `--`, or a Generated value (spawn.rs).
# 2. No shell anywhere: no "sh", "bash", "dash", "zsh", "/bin/sh", "-c", `system(`, `popen`, or `exec*`
#    from libc.
# 3. No string-built command line: no `format!` or `concat!` in spawn.rs outside the constructors of
#    Generated (whose input is a UUID, a number, or 32 hex digits) and the agent's own notes.
#
# Exits 1 and prints each offending line when the check fails.
set -eu

if [ "${1:-}" = --self-test ]; then
    here=$(cd "$(dirname "$0")" && pwd)
    src=$(cd "$here/.." && pwd)/src/tasks
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    case_n=0
    expect_fail() {
        case_n=$((case_n + 1))
        rm -rf "$work/tasks" && cp -R "$src" "$work/tasks"
        printf '%s\n' "$2" >> "$work/tasks/$1"
        if "$0" "$work/tasks" > /dev/null 2>&1; then
            echo "check-task-spawns self-test: case $case_n was not caught: $1 += $2" >&2
            exit 1
        fi
    }
    expect_fail wire.rs 'fn x() { let _ = std::process::Command::new("/bin/sh"); }'
    expect_fail wire.rs 'fn x(c: &mut Cmd) { c.arg("-c"); }'
    expect_fail wire.rs 'const S: &str = "bash";'
    # Code after a test module is still checked (review of #168).
    expect_fail wire.rs '#[cfg(test)]
mod tests {
    fn t() {}
}
fn after() { let _ = std::process::Command::new("/usr/bin/true"); }'
    expect_fail executor/spawn.rs 'fn y() -> String { format!("--{}", 1) }'
    # Test code may use a shell.
    rm -rf "$work/tasks" && cp -R "$src" "$work/tasks"
    printf '#[cfg(test)]\nmod tests {\n    const S: &str = "/bin/sh";\n}\n' >> "$work/tasks/settings.rs"
    "$0" "$work/tasks" > /dev/null || { echo "check-task-spawns self-test: test code was flagged" >&2; exit 1; }
    echo "check-task-spawns self-test: $case_n bypasses caught, test code allowed"
    exit 0
fi

dir=${1:-src/tasks}
spawn="$dir/executor/spawn.rs"
[ -f "$spawn" ] || { echo "check-task-spawns: $spawn is missing" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Non-test code of each file, as "path:line:text".
find "$dir" -name '*.rs' ! -name tests.rs | sort | while IFS= read -r file; do
    # A `#[cfg(test)]` line followed by `mod tests {` starts a test module, which ends at the next `}` in
    # column 0 (rustfmt indents everything inside it). Its lines are left out; every line after it is
    # checked again, so code placed after a test module cannot escape the check (review of #168).
    awk -v f="$file" '
        skipping { if ($0 ~ /^\}/) skipping = 0; next }
        $0 ~ /^mod tests \{/ && held && line == "#[cfg(test)]" { held = 0; skipping = 1; next }
        held { print f ":" n ":" line }
        { line = $0; n = NR; held = 1 }
        END { if (held) print f ":" n ":" line }
    ' "$file"
done > "$tmp/code"

status=0
fail() {
    echo "check-task-spawns: $1" >&2
    printf '%s\n' "$2" >&2
    status=1
}

# 1. Process creation only in spawn.rs.
found=$(grep -v "^$spawn:" "$tmp/code" | grep -E 'process::Command|\bCommand::|\.args?\(|\.envs?\(' || true)
[ -z "$found" ] || fail "a process is built outside $spawn" "$found"
count=$(grep "^$spawn:" "$tmp/code" | grep -c 'Command::new(' || true)
[ "$count" -eq 1 ] || fail "$spawn must call Command::new exactly once (found $count)" ""

# 2. No shell.
found=$(grep -E '"(/usr)?(/bin/)?(sh|bash|dash|zsh|ksh)"|"-c"|\bsystem\(|popen|libc::exec' "$tmp/code" || true)
[ -z "$found" ] || fail "a shell (or exec) appears in the task module" "$found"

# 3. No string-built command line in spawn.rs, except Generated's constructors and notes.
found=$(grep "^$spawn:" "$tmp/code" | grep -E 'format!|concat!' \
    | grep -Ev 'Self\(format!\("(fleet-agent-task-\{task_id\}-\{step\}\.service|--property=RuntimeMaxSec=\{seconds\}|_SYSTEMD_INVOCATION_ID=\{invocation\})"\)\)|\.note\(&format!\("could not start' || true)
[ -z "$found" ] || fail "a string is formatted in $spawn outside Generated's constructors" "$found"

if [ "$status" -eq 0 ]; then
    lines=$(wc -l < "$tmp/code")
    echo "check-task-spawns: no shell, and every task process goes through $spawn ($lines lines checked)"
fi
exit "$status"
