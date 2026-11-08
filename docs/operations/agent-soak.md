# Agent soak test

`agent/scripts/soak.sh` (P1-A09) runs the installed agent for days against a stand-in server that goes down and flaps, puts it through one update and one forced rollback, and samples it for leaks. `agent/scripts/soak-analyse.py` judges the samples. One 72-hour run that passes, with its summary and samples attached to the delivery note, is required in Phase 2 ([P2-SOAK](../backlog/specs/p2-soak.md)); it was deferred from Phase 1 so that nothing is deployed yet.

## What a run does

| When | What happens |
|---|---|
| Start | 1.0.0 is installed with the real units and layout, heartbeating every 10 s and reporting every 60 s to `scripts/update-stub.py`. |
| 30 minutes | The server offers 1.0.1, a real build: it must be installed and confirmed. |
| 60 minutes | The server offers 1.0.2, which crash-loops: it must be rolled back to 1.0.1. |
| Then, every 4 hours | The server is down for 10 minutes, then up and down every 30 seconds for 10 minutes, then up. |
| End | Only the versions `current` and `previous` point to are installed, and nothing is left of staging, the backup, the update record, or the result. |

Every minute, and as the update and rollback start and end, a sample records the agent's main PID, version, systemd restart count, resident memory, open descriptors, threads, the state directory's size and entries, and the installed versions.

## The verdict

The measured window is everything after the rollback, less its first tenth (warm-up). The run passes when:

| Check | Tolerance |
|---|---|
| Complete | The samples cover the whole run. |
| No restarts | The main PID and the restart count change only during the update and the rollback, never in an outage, flapping, or steady period. |
| Outages | The window includes outages and flapping periods. |
| Memory | The median of the window's last quarter is at most 10% (and at least 1 MiB) above its first quarter's. |
| Descriptors, threads | The last quarter's highest count is no higher than the first quarter's. |
| State directory | No more entries in the last quarter than in the first, and at most 512 bytes larger (records are rewritten in place, and a number in one can gain a digit). |

`summary.md` also gives each measure's trend per hour.

## Running the 72-hour soak

It rewrites `/usr/lib/fleet-agent`, `/etc/fleet-agent`, `/var/lib/fleet-agent`, and two units, and refuses to run where an agent is installed, so use a disposable VM (Debian 13, systemd). It needs no network: the server is local.

On a machine with the Rust toolchain and `minisign`, from `agent/`, build two versions that trust a throwaway key:

```sh
dir=$HOME/soak-build && mkdir -p "$dir"
minisign -G -W -p "$dir/test.pub" -s "$dir/test.key"
scripts/update-smoke-build.sh 1.0.0 "$dir/test.pub" "$dir/fleet-agent-1.0.0"
scripts/update-smoke-build.sh 1.0.1 "$dir/test.pub" "$dir/fleet-agent-1.0.1"
```

Copy that directory and the repository's `agent/` directory to the VM. On the VM, from `agent/`:

```sh
sudo apt-get install -y --no-install-recommends jq minisign openssl python3
sudo systemd-run --unit=fleet-soak --setenv=SOAK_DISPOSABLE=yes --working-directory="$PWD" \
  "$PWD/scripts/soak.sh" "$HOME/soak-build" "$HOME/soak-results"
journalctl -fu fleet-soak      # follow it; it ends after 72 hours
```

Running it as a transient unit keeps it going after you log out. `SOAK_HOURS`, `SOAK_SAMPLE_SECONDS`, `SOAK_CYCLE_MINUTES`, `SOAK_OUTAGE_SECONDS`, and `SOAK_FLAP_SECONDS` (each with `--setenv`) change the schedule. The unit exits 0 when every check passes. `$HOME/soak-results` then holds `summary.md`, `samples.csv`, `events.log`, and the agent's journal; attach `summary.md` and `samples.csv` to the Phase 2 delivery note. The throwaway key never leaves the build machine and the VM; delete both afterwards.

The **Agent soak** workflow runs the same script for 30 minutes on a pull request that changes it, and for up to 5 hours by hand, to check the tooling. It cannot replace the 72-hour run.
