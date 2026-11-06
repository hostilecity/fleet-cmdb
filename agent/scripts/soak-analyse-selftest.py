#!/usr/bin/env python3
"""Self-test of scripts/soak-analyse.py (P1-A09), without an agent: a clean synthetic run passes, and each kind
of leak, a restart during an outage, a short run, and a run without the update fail the check they should.

    scripts/soak-analyse-selftest.py
"""
import contextlib
import csv
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("soak_analyse", os.path.join(HERE, "soak-analyse.py"))
soak = importlib.util.module_from_spec(spec)
spec.loader.exec_module(soak)

FIELDS = "epoch,elapsed_s,phase,pid,version,restarts,rss_kib,fds,threads,state_bytes,state_entries,versions,server_up".split(",")
HOURS = 6


def run(**change):
    """A synthetic 6-hour run sampled every minute: update at 30 min, rollback at 60, then outages and flapping
    every hour. change(row, i) may alter any sample."""
    rows = []
    for i in range(HOURS * 60 + 1):
        elapsed = i * 60
        pid, version, restarts = 100, "1.0.0", 0
        if 30 <= i < 33:
            phase = "update"
        elif 60 <= i < 64:
            phase = "rollback"
        elif i < 30:
            phase = "start"
        elif i < 60:
            phase = "between"
        else:
            phase = ("outage", "flap")[((i - 64) % 60) // 10] if (i - 64) % 60 < 20 else "steady"
        if i >= 32:
            pid, version = 200, "1.0.1"
        if i >= 62:
            pid, restarts = 300, 3
        row = dict(epoch=1_700_000_000 + elapsed, elapsed_s=elapsed, phase=phase, pid=pid, version=version, restarts=restarts,
                   rss_kib=6000 + (i * 7919) % 300, fds=12 + (phase == "flap"), threads=5, state_bytes=4096 + (i % 3),
                   state_entries=4, versions=2, server_up=int(phase != "outage"))
        for fn in change.values():
            fn(row, i)
        if not row.pop("drop", False):
            rows.append(row)
    return rows


def verdict(rows, hours=HOURS):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "samples.csv")
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
        loaded = soak.load(path)
        checks, _, _ = soak.analyse(loaded, hours)
        with open(os.devnull, "w") as quiet, contextlib.redirect_stdout(quiet):
            soak.main([path, os.path.join(tmp, "summary.md"), "--hours", str(hours)])
    return {name for name, passed, _ in checks if not passed}


def leak_memory(row, i):
    row["rss_kib"] += i * 10  # about 600 KiB an hour


def leak_descriptors(row, i):
    row["fds"] += i // 120


def grow_threads(row, i):
    row["threads"] += i // 300


def grow_state(row, i):
    row["state_entries"] += i // 200
    row["state_bytes"] += i * 4


def restart_in_outage(row, i):
    if i >= 200:
        row["pid"] = 400


def restart_after_rollback(row, i):
    # The first sample after the rollback ended (i == 64, steady) already shows a new process.
    if i >= 64:
        row["pid"] = 500


def gap_in_the_middle(row, i):
    if 100 <= i < 160:  # an hour with no samples
        row["drop"] = True


def late_first_sample(row, i):
    if i < 5:
        row["drop"] = True


def not_running(row, i):
    if i == 150:
        row["pid"], row["rss_kib"], row["fds"], row["threads"] = 0, None, None, None


def no_update(row, i):
    if row["phase"] in ("update", "rollback"):
        row["phase"] = "between"


CASES = [
    ("a clean run", {}, set(), HOURS),
    ("growing memory", {"m": leak_memory}, {"memory"}, HOURS),
    ("growing descriptors", {"m": leak_descriptors}, {"descriptors"}, HOURS),
    ("growing threads", {"m": grow_threads}, {"threads"}, HOURS),
    ("a growing state directory", {"m": grow_state}, {"state"}, HOURS),
    ("a restart during an outage", {"m": restart_in_outage}, {"no restarts"}, HOURS),
    ("the agent not running", {"m": not_running}, {"no restarts"}, HOURS),
    ("a restart just after the rollback ended", {"m": restart_after_rollback}, {"no restarts"}, HOURS),
    ("an hour without samples", {"m": gap_in_the_middle}, {"complete"}, HOURS),
    ("no samples at the start", {"m": late_first_sample}, {"complete"}, HOURS),
    ("a run shorter than asked", {}, {"complete"}, 72),
]

failures = 0
for name, change, expected, hours in CASES:
    got = verdict(run(**change), hours)
    status = "ok" if got == expected else "WRONG"
    failures += got != expected
    print(f"soak-analyse selftest: {name}: failed {sorted(got) or 'nothing'} ({status}, expected {sorted(expected) or 'nothing'})", file=sys.stderr)
# Without the update and rollback there is no measured window at all.
got = verdict(run(m=no_update))
ok = {"update", "measured window"} <= got
failures += not ok
print(f"soak-analyse selftest: no update: failed {sorted(got)} ({'ok' if ok else 'WRONG'})", file=sys.stderr)
sys.exit(1 if failures else 0)
