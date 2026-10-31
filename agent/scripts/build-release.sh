#!/bin/sh
# Builds the release binary reproducibly (P1-PACKAGING, review of #72), as both the release workflow and
# Agent CI do:
#
#   scripts/build-release.sh TARGET [TARGET_DIR]      (run from agent/; prints the binary's path)
#
# The same commit, toolchain, and target give a byte-identical binary wherever it is built: the source
# directory, Cargo's home, and the target directory are remapped out of the binary, so the build
# directory leaves no trace. The release workflow builds twice on separate runners and signs only if both
# binaries are identical; Agent CI builds twice in different directories on every change, so a release
# never finds out late that the build stopped being reproducible.
set -eu

target=${1:?usage: scripts/build-release.sh TARGET [TARGET_DIR]}
target_dir=${2:-target}
mkdir -p "$target_dir"
target_dir=$(cd "$target_dir" && pwd)
cargo_home=${CARGO_HOME:-$HOME/.cargo}

RUSTFLAGS="--remap-path-prefix=$(pwd)=/build/agent --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$target_dir=/build/target" \
CARGO_INCREMENTAL=0 \
    cargo build --release --locked --target "$target" --target-dir "$target_dir" >&2

echo "$target_dir/$target/release/fleet-agent"
