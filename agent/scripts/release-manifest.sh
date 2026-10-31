#!/bin/sh
# Prints the release manifest for one agent binary (P1-PACKAGING; format in docs/releases.md).
#
#   scripts/release-manifest.sh VERSION TARGET BINARY > fleet-agent-VERSION-TARGET.manifest.json
#
# The manifest is what the release key signs. Every value is checked before it is written, so the JSON
# needs no escaping. The agent checks it again, strictly, after verifying the signature.
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 VERSION TARGET BINARY" >&2
    exit 2
fi
version=$1
target=$2
binary=$3

semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if ! printf '%s\n' "$version" | grep -Eq "$semver"; then
    echo "$0: not a SemVer version without build metadata: $version" >&2
    exit 1
fi
if ! printf '%s\n' "$target" | grep -Eq '^[a-z0-9_]+(-[a-z0-9_]+)+$'; then
    echo "$0: not a target triple: $target" >&2
    exit 1
fi
if [ ! -f "$binary" ]; then
    echo "$0: not a file: $binary" >&2
    exit 1
fi

sha256=$(sha256sum "$binary" | cut -d ' ' -f 1)
size=$(wc -c < "$binary" | tr -d ' ')
if [ "$size" -eq 0 ]; then
    echo "$0: empty binary: $binary" >&2
    exit 1
fi

printf '{"format":"fleet-agent-release-manifest/1","version":"%s","target":"%s","sha256":"%s","size":%s}\n' \
    "$version" "$target" "$sha256" "$size"
