#!/usr/bin/env python3
"""Checks a release version is newer than every earlier release (Agent release workflow, ADR 0018).

    git tag --list 'agent-v*' | sed 's/^agent-v//' | scripts/check-release-version.py VERSION

Reads the earlier versions, one per line, on stdin. Compares by SemVer 2.0.0 precedence: a pre-release sorts
before its release (1.2.0-rc.1 < 1.2.0), numeric identifiers compare as numbers and sort before alphanumeric
ones. Lines that are not SemVer are ignored, so a stray tag cannot block a release. Exits 1 with a GitHub
Actions error when VERSION is not newer than the newest earlier release.
"""
import re
import sys

SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def key(version):
    match = SEMVER.fullmatch(version)
    if not match:
        return None
    core = tuple(int(part) for part in match.group(1, 2, 3))
    pre = match.group(4)
    if pre is None:
        return (core, (1,))  # a release sorts after all of its pre-releases
    ids = tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in pre.split("."))
    return (core, (0, ids))


def main():
    if len(sys.argv) != 2 or key(sys.argv[1]) is None:
        print("usage: check-release-version.py VERSION (SemVer), earlier versions on stdin", file=sys.stderr)
        return 2
    version = sys.argv[1]
    earlier = [line.strip() for line in sys.stdin if key(line.strip()) is not None]
    if not earlier:
        print(f"{version} is the first release")
        return 0
    newest = max(earlier, key=key)
    if key(version) <= key(newest):
        print(f"::error::{version} is not newer than the newest release, {newest}; choose a newer version")
        return 1
    print(f"{version} is newer than the newest release, {newest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
