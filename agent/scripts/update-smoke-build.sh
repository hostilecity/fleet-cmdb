#!/bin/sh
# Builds the musl agent as one version of a test release line, trusting a throwaway release key, for
# scripts/update-smoke.sh (P1-AGENT-UPDATE):
#
#   scripts/update-smoke-build.sh VERSION PUBKEY OUT [TARGET_DIR]      (run from agent/)
#
# The sources (and the task catalog they compile in) are copied to a fixed directory first, with the package version and release-keys/current.pub
# changed there, so the working tree is never touched and no key can end up committed. The same directory
# and RUSTFLAGS are used for every version, so after the first build only the agent itself is compiled.
set -eu

version=${1:?usage: scripts/update-smoke-build.sh VERSION PUBKEY OUT [TARGET_DIR]}
pubkey=${2:?usage: scripts/update-smoke-build.sh VERSION PUBKEY OUT [TARGET_DIR]}
out=${3:?usage: scripts/update-smoke-build.sh VERSION PUBKEY OUT [TARGET_DIR]}
target_dir=${4:-${TMPDIR:-/tmp}/update-smoke-target}
target=x86_64-unknown-linux-musl

if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "update-smoke-build: not a plain version: $version" >&2
    exit 2
fi
here=$(pwd)
root=${TMPDIR:-/tmp}/update-smoke-src
work=$root/agent
rm -rf "$root"
mkdir -p "$work" "$root/docs/api/tasks"
tar --exclude=./target -cf - . | tar -xf - -C "$work"
# The build compiles in the shared task catalog from outside the crate (P3-A01).
cp ../docs/api/tasks/task-catalog.json "$root/docs/api/tasks/"

cp "$pubkey" "$work/release-keys/current.pub"
sed -i "0,/^version = \"[^\"]*\"/s//version = \"$version\"/" "$work/Cargo.toml"
awk -v v="$version" '
    /^name = "fleet-agent"$/ { hit = 1 }
    hit && /^version = / { print "version = \"" v "\""; hit = 0; next }
    { print }
' "$work/Cargo.lock" > "$work/Cargo.lock.new"
mv "$work/Cargo.lock.new" "$work/Cargo.lock"

built=$(cd "$work" && scripts/build-release.sh "$target" "$target_dir")
install -D -m 0755 "$built" "$out"
"$out" --version | grep -Fx "fleet-agent $version (agent schema 1)" > /dev/null
echo "built $out (fleet-agent $version, trusts $(basename "$pubkey"))" >&2
cd "$here"
