#!/usr/bin/env python3
"""Verdict on an agent soak run (P1-A09), from the samples scripts/soak.sh wrote.

    soak-analyse.py SAMPLES.csv SUMMARY.md [--hours H]

Writes a Markdown summary and exits 1 when a check fails. The checks, and the tolerances they allow:

  complete      the samples cover the run (H hours, less two sample intervals)
  update        an update and a forced rollback both happened
  no restarts   the agent's main PID and systemd's restart count change only during the update and the
                rollback: never during an outage, flapping, or a steady period, and the agent is always running
  outages       the measured window includes at least one outage and one flapping period
  memory        resident memory: the median of the last quarter of the measured window is at most 10% (and at
                least 1 MiB) above the median of the first quarter
  descriptors   the most open descriptors in the last quarter is no more than in the first quarter
  threads       likewise for threads
  state         the state directory: no more entries in the last quarter than in the first, and its size at
                most 512 bytes above the first quarter's largest (records are rewritten in place, and a number
                in one can gain a digit)

The measured window is everything after the rollback, less the first tenth of it (warm-up).
"""
import argparse
import csv
import statistics
import sys

ALLOWED = {"update", "rollback"}
MEMORY_TOLERANCE = 0.10
MEMORY_SLACK_KIB = 1024
STATE_SLACK_BYTES = 512


def load(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        for key in ("epoch", "elapsed_s", "pid", "restarts", "state_bytes", "state_entries", "versions"):
            row[key] = int(row[key])
        for key in ("rss_kib", "fds", "threads"):
            row[key] = int(row[key]) if row[key] else None
    return rows


def restarts_outside_updates(rows):
    problems = []
    for before, after in zip(rows, rows[1:]):
        if before["phase"] in ALLOWED or after["phase"] in ALLOWED:
            continue
        if after["pid"] == 0:
            problems.append(f"no agent process at {after['elapsed_s']}s ({after['phase']})")
        elif before["pid"] != after["pid"] or before["restarts"] != after["restarts"]:
            problems.append(
                f"restarted between {before['elapsed_s']}s and {after['elapsed_s']}s ({before['phase']} -> {after['phase']}): "
                f"pid {before['pid']} -> {after['pid']}, restarts {before['restarts']} -> {after['restarts']}"
            )
    return problems


def window(rows):
    """Samples after the rollback, less the first tenth of that time."""
    last_allowed = max((i for i, r in enumerate(rows) if r["phase"] in ALLOWED), default=None)
    after = rows[last_allowed + 1:] if last_allowed is not None else []
    if not after:
        return []
    begin = after[0]["elapsed_s"] + (after[-1]["elapsed_s"] - after[0]["elapsed_s"]) / 10
    return [r for r in after if r["elapsed_s"] >= begin and r["pid"] != 0]


def quarters(rows):
    size = max(len(rows) // 4, 1)
    return rows[:size], rows[-size:]


def slope_per_hour(rows, key):
    points = [(r["elapsed_s"] / 3600, r[key]) for r in rows if r[key] is not None]
    if len(points) < 2:
        return 0.0
    mean_x = statistics.fmean(x for x, _ in points)
    mean_y = statistics.fmean(y for _, y in points)
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator if denominator else 0.0


def values(rows, key):
    return [r[key] for r in rows if r[key] is not None]


def analyse(rows, hours):
    checks = []

    def check(name, passed, detail):
        checks.append((name, bool(passed), detail))

    sample_interval = statistics.median(b["epoch"] - a["epoch"] for a, b in zip(rows, rows[1:])) if len(rows) > 1 else 0
    covered = rows[-1]["elapsed_s"] if rows else 0
    check("complete", covered >= hours * 3600 - 2 * sample_interval, f"{covered / 3600:.2f} h of {hours} h, {len(rows)} samples")
    phases = {r["phase"] for r in rows}
    check("update", {"update", "rollback"} <= phases, "update and rollback seen" if {"update", "rollback"} <= phases else f"phases seen: {sorted(phases)}")
    problems = restarts_outside_updates(rows)
    check("no restarts", not problems, "; ".join(problems[:5]) or "the agent kept one process through every outage and flapping period")

    measured = window(rows)
    stats = {}
    if len(measured) < 8:
        check("measured window", False, f"only {len(measured)} samples after the rollback and warm-up")
        return checks, stats, measured
    outages = sum(1 for a, b in zip(measured, measured[1:]) if a["phase"] != "outage" and b["phase"] == "outage")
    outages += measured[0]["phase"] == "outage"
    flaps = sum(1 for a, b in zip(measured, measured[1:]) if a["phase"] != "flap" and b["phase"] == "flap")
    flaps += measured[0]["phase"] == "flap"
    check("outages", outages >= 1 and flaps >= 1, f"{outages} outages and {flaps} flapping periods in the measured window")

    first, last = quarters(measured)
    for key in ("rss_kib", "fds", "threads", "state_bytes", "state_entries"):
        stats[key] = {
            "first_median": statistics.median(values(first, key)),
            "last_median": statistics.median(values(last, key)),
            "first_max": max(values(first, key)),
            "last_max": max(values(last, key)),
            "slope_per_hour": slope_per_hour(measured, key),
        }
    rss = stats["rss_kib"]
    limit = max(rss["first_median"] * (1 + MEMORY_TOLERANCE), rss["first_median"] + MEMORY_SLACK_KIB)
    check("memory", rss["last_median"] <= limit,
          f"median {rss['first_median']} KiB -> {rss['last_median']} KiB (limit {limit:.0f}), trend {rss['slope_per_hour']:+.1f} KiB/h")
    for key, name in (("fds", "descriptors"), ("threads", "threads")):
        s = stats[key]
        check(name, s["last_max"] <= s["first_max"], f"most {s['first_max']} -> {s['last_max']}")
    entries, size = stats["state_entries"], stats["state_bytes"]
    check("state", entries["last_max"] <= entries["first_max"] and size["last_max"] <= size["first_max"] + STATE_SLACK_BYTES,
          f"entries {entries['first_max']} -> {entries['last_max']}, bytes {size['first_max']} -> {size['last_max']}")
    return checks, stats, measured


def markdown(rows, hours, checks, stats, measured):
    lines = ["# Agent soak results", ""]
    if rows:
        versions = sorted({r["version"] for r in rows})
        lines.append(f"{len(rows)} samples over {rows[-1]['elapsed_s'] / 3600:.2f} h (target {hours} h); versions run: {', '.join(versions)}.")
    if measured:
        lines.append(f"Measured window: {measured[0]['elapsed_s'] / 3600:.2f} h to {measured[-1]['elapsed_s'] / 3600:.2f} h, {len(measured)} samples, "
                     f"pid {measured[0]['pid']}, version {measured[-1]['version']}.")
    if stats:
        lines += ["", "| Measure | First quarter median | Last quarter median | First quarter max | Last quarter max | Trend per hour |",
                  "|---|---|---|---|---|---|"]
        for key, label in (("rss_kib", "Resident memory (KiB)"), ("fds", "Open descriptors"), ("threads", "Threads"),
                           ("state_bytes", "State directory (bytes)"), ("state_entries", "State directory entries")):
            s = stats[key]
            lines.append(f"| {label} | {s['first_median']} | {s['last_median']} | {s['first_max']} | {s['last_max']} | {s['slope_per_hour']:+.2f} |")
    lines += ["", "## Checks", ""] + [f"- [{'x' if passed else ' '}] {name}: {detail}" for name, passed, detail in checks]
    verdict = "PASSED" if checks and all(passed for _, passed, _ in checks) else "FAILED"
    lines += ["", f"**{verdict}**", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("samples")
    parser.add_argument("summary")
    parser.add_argument("--hours", type=float, default=72)
    args = parser.parse_args(argv)
    rows = load(args.samples)
    checks, stats, measured = analyse(rows, args.hours)
    text = markdown(rows, args.hours, checks, stats, measured)
    with open(args.summary, "w") as f:
        f.write(text)
    print(text)
    return 0 if all(passed for _, passed, _ in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
