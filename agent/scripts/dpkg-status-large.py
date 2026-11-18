#!/usr/bin/env python3
"""Writes a dpkg database with COUNT installed packages, for measuring the agent on a large host (#182).

    dpkg-status-large.py SOURCE_STATUS COUNT OUT_DIR

The packages are the installed ones of SOURCE_STATUS (normally /var/lib/dpkg/status), copied as often as
needed with a numbered suffix on each name (`libc6` becomes `libc6-n00001`), so every stanza is the size
and shape of a real one: maintainer, dependencies, description and all. OUT_DIR gets `status`, an empty
`updates/` and `info/`, and the `arch` file if the source has one: enough for `dpkg-query --show`, and
what scripts/sandbox-smoke.sh binds over /var/lib/dpkg for one run of the agent. 20,000 is the most a
package report may list (MAX_PACKAGES in src/packages.rs). Nothing on the machine running it changes.
"""
import os
import re
import shutil
import sys

source, count, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(source, encoding="utf-8", errors="surrogateescape") as f:
    stanzas = [s for s in f.read().split("\n\n") if s.strip()]
installed = [s for s in stanzas if re.search(r"^Status: install ok installed$", s, re.M)]
if not installed:
    sys.exit(f"dpkg-status-large: no installed package in {source}")

os.makedirs(os.path.join(out, "updates"), exist_ok=True)
os.makedirs(os.path.join(out, "info"), exist_ok=True)
arch = os.path.join(os.path.dirname(source), "arch")
if os.path.exists(arch):
    shutil.copy(arch, os.path.join(out, "arch"))
with open(os.path.join(out, "status"), "w", encoding="utf-8", errors="surrogateescape") as f:
    for i in range(count):
        stanza = installed[i % len(installed)]
        name = re.search(r"^Package: (\S+)$", stanza, re.M).group(1)
        stanza = re.sub(r"^Package: \S+$", f"Package: {name}-n{i:05d}", stanza, count=1, flags=re.M)
        f.write(stanza.strip("\n") + "\n\n")
print(f"dpkg-status-large: {count} installed packages in {out}/status "
      f"({os.path.getsize(os.path.join(out, 'status'))} bytes, from {len(installed)} in {source})")
