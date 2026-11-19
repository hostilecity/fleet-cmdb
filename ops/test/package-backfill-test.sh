#!/usr/bin/env bash
# Tests ops/backup/package-backfill.sh (#196's upgrade step) against a stub `docker`, for the paths a real app in
# Deploy CI does not reach: the lock held while it waits for /up, the restore marker checked again once the lock is
# held, an interrupt during the backfill, a crash-looping restart, and a refusal after the restart. Deploy CI runs it;
# it needs bash, flock and perl. The stub runs the script's `docker exec` commands on this machine, in a directory
# that stands for the container (with its own bin/rails and curl), and keeps the container's state in files.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backup/package-backfill.sh"
failed=0
ok() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failed=1; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1: expected '$2', got '$3'"; fi; }
contains() { if [[ "$3" == *"$2"* ]]; then ok "$1"; else fail "$1: '$2' not in: $3"; fi; }
lacks() { if [[ "$3" != *"$2"* ]]; then ok "$1"; else fail "$1: '$2' in: $3"; fi; }

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# A fresh stub: HOME, the stub's bin, the "container" directory, and its state. Options as files in $state:
# backfill (ok | slow | fail), up_after (the /up call that first answers), after_restart (serve | crash | restarting |
# stop | refuse), pid_delay (seconds before the backfill writes its pid).
setup() {
  local dir="$root/$1"
  mkdir -p "$dir/home" "$dir/bin" "$dir/ctr/bin" "$dir/ctr/tmp" "$dir/state"
  export HOME="$dir/home" STUB_STATE="$dir/state" STUB_CTR="$dir/ctr" PATH="$dir/bin:$base_path"
  lock="$HOME/.local/state/fleet-cmdb/backup.lock" marker="$HOME/.local/state/fleet-cmdb/restore-incomplete"
  mkdir -p "$(dirname "$lock")"
  echo true > "$STUB_STATE/running"
  echo 0 > "$STUB_STATE/restart_count"
  echo ok > "$STUB_STATE/backfill"
  echo 3 > "$STUB_STATE/up_after"
  echo serve > "$STUB_STATE/after_restart"
  echo false > "$STUB_STATE/restarting"
  echo 0 > "$STUB_STATE/pid_delay"
  : > "$STUB_STATE/events"
  : > "$STUB_STATE/logs"

  cat > "$dir/bin/docker" << 'EOF'
#!/usr/bin/env bash
s="$STUB_STATE"
cmd="$1"; shift
case "$cmd" in
  inspect)
    case "$2" in
      *State.Running*) cat "$s/running" ;;
      *State.Restarting*) cat "$s/restarting" ;;
      *RestartCount*) cat "$s/restart_count" ;;
      *) echo "unknown format $2" >&2; exit 1 ;;
    esac ;;
  exec)
    shift
    case "$*" in *packages:backfill*) sleep "$(cat "$s/pid_delay")" ;; esac # a slow docker exec start
    cd "$STUB_CTR" && PATH="$STUB_CTR/bin:$PATH" exec "$@" ;;
  restart) echo restarted >> "$s/events" ;;
  logs) cat "$s/logs" ;;
  *) echo "unknown docker command $cmd" >&2; exit 1 ;;
esac
EOF
  # Perl, not bash: a background job's shell ignores SIGINT and cannot trap it.
  cat > "$dir/ctr/bin/rails" << 'EOF'
#!/usr/bin/env perl
my $s = $ENV{STUB_STATE};
open(my $f, '<', "$s/backfill"); chomp(my $mode = <$f>); close($f);
sub event { open(my $e, '>>', "$s/events"); print $e "$_[0]\n"; close($e); }
if ($mode eq 'fail') { print STDERR "backfill failed\n"; exit 1; }
if ($mode eq 'slow') {
  $SIG{INT} = sub { event('backfill interrupted'); exit 130; };
  event('backfill started');
  sleep 30 for 1 .. 4;
  event('backfill finished');
  exit 0;
}
print "nothing to move\n";
EOF
  # Each /up call: notes whether the backup lock is free meanwhile, then answers from the up_after'th call on.
  cat > "$dir/ctr/bin/curl" << 'EOF'
#!/usr/bin/env bash
s="$STUB_STATE"
n=$(( $(cat "$s/calls" 2> /dev/null || echo 0) + 1 )); echo "$n" > "$s/calls"
flock -n "$HOME/.local/state/fleet-cmdb/backup.lock" true 9>&- && echo "lock free during /up" >> "$s/events"
case "$(cat "$s/after_restart")" in
  crash) echo $(( $(cat "$s/restart_count") + 1 )) > "$s/restart_count"; exit 7 ;;
  restarting) echo true > "$s/restarting"; exit 7 ;;
  stop) echo false > "$s/running"; exit 7 ;;
  refuse) echo "fleet-cmdb upgrade step needed: still too long" >> "$s/logs"; exit 7 ;;
esac
[ "$n" -ge "$(cat "$s/up_after")" ]
EOF
  chmod +x "$dir/bin/docker" "$dir/ctr/bin/rails" "$dir/ctr/bin/curl"
}
run() { FLEET_BACKFILL_UP_WAIT="${1:-60}" "$script" 2>&1 && echo "rc=0" || echo "rc=$?"; }
base_path="$PATH"
command -v perl > /dev/null || { echo "perl is needed"; exit 1; }

echo "-- success: backfills, restarts, and holds the lock until /up answers on both ports"
setup success
echo 4 > "$STUB_STATE/up_after" # 3000 fails, fails, fails, then answers; then 3443
out="$(run)"
contains "it ends serving" "serves again" "$out"
contains "with rc 0" "rc=0" "$out"
contains "after a restart" "restarted" "$(cat "$STUB_STATE/events")"
lacks "the lock was held through every /up call" "lock free during /up" "$(cat "$STUB_STATE/events")"
expect "both ports were checked once 3000 answered" 5 "$(cat "$STUB_STATE/calls")"
contains "its holder line" "package backfill since " "$(cat "$lock")"

echo "-- an unfinished restore's marker written while it waited for the lock"
setup marker
# shellcheck disable=SC2016 # expanded by sh
flock "$lock" sh -c 'echo "backup (test) running" > "$1"; sleep 3' sh "$lock" & holder=$!
sleep 1
(sleep 1; echo "the restore of fleet-cmdb-test did not finish" > "$marker") &
out="$(run)"
wait "$holder" || true
contains "it waited for the backup" "waiting for: backup (test)" "$out"
contains "then refused on the second marker check" "refused: the restore of fleet-cmdb-test did not finish" "$out"
lacks "without restarting the app" "restarted" "$(cat "$STUB_STATE/events")"

echo "-- the container is not running"
setup stopped
echo false > "$STUB_STATE/running"
contains "it refuses" "is not running: deploy first" "$(run)"

echo "-- the backfill fails"
setup failing
echo fail > "$STUB_STATE/backfill"
out="$(run)"
contains "it stops" "the backfill stopped (above)" "$out"
lacks "without restarting the app" "restarted" "$(cat "$STUB_STATE/events")"

echo "-- interrupted during the backfill"
setup interrupted
echo slow > "$STUB_STATE/backfill"
FLEET_BACKFILL_UP_WAIT=60 "$script" > "$root/interrupted.log" 2>&1 & pid=$!
for _ in $(seq 1 50); do grep -q "backfill started" "$STUB_STATE/events" && break; sleep 0.2; done
kill -TERM "$pid"
wait "$pid" && rc=0 || rc=$?
out="$(cat "$root/interrupted.log")"
expect "it fails" 1 "$rc"
contains "after stopping the backfill" "backfill interrupted" "$(cat "$STUB_STATE/events")"
contains "and says the app still waits" "was not restarted and still waits" "$out"
lacks "without restarting the app" "restarted" "$(cat "$STUB_STATE/events")"
if flock -n "$lock" true; then ok "the lock is released"; else fail "the lock is still held"; fi

echo "-- the restarted container crash-loops"
setup crash
echo crash > "$STUB_STATE/after_restart"
start=$(date +%s)
out="$(run 40)"
contains "it stops waiting" "exited and was restarted while it started" "$out"
expect "at once, not after FLEET_BACKFILL_UP_WAIT" yes "$([ $(($(date +%s) - start)) -lt 30 ] && echo yes || echo no)"

echo "-- the restarted container is restarting by itself"
setup restarting
echo restarting > "$STUB_STATE/after_restart"
contains "it stops waiting" "exited and was restarted while it started" "$(run 20)"

echo "-- the restarted container stops"
setup stop
echo stop > "$STUB_STATE/after_restart"
contains "it stops waiting" "stopped while it started" "$(run 20)"

echo "-- the restarted container refuses again"
setup refuse
echo refuse > "$STUB_STATE/after_restart"
contains "it says so" "refused the upgrade again" "$(run 20)"

echo "-- interrupted once while it waits for /up: it keeps waiting, and the lock"
setup up_once
echo 1000 > "$STUB_STATE/up_after"
FLEET_BACKFILL_UP_WAIT=60 "$script" > "$root/up_once.log" 2>&1 & pid=$!
for _ in $(seq 1 50); do grep -q "restarting fleet-cmdb" "$root/up_once.log" && break; sleep 0.2; done
kill -TERM "$pid"
sleep 6
contains "it says it still waits" "still waiting for fleet-cmdb's migrations" "$(cat "$root/up_once.log")"
if flock -n "$lock" true; then fail "the lock was released"; else ok "the lock is still held"; fi
echo 0 > "$STUB_STATE/up_after" # the migrations end
wait "$pid" && rc=0 || rc=$?
expect "then it ends serving" 0 "$rc"
contains "with its done line" "serves again" "$(cat "$root/up_once.log")"

echo "-- interrupted twice while it waits for /up: it stops waiting"
setup up_twice
echo 1000 > "$STUB_STATE/up_after"
FLEET_BACKFILL_UP_WAIT=60 "$script" > "$root/up_twice.log" 2>&1 & pid=$!
for _ in $(seq 1 50); do grep -q "restarting fleet-cmdb" "$root/up_twice.log" && break; sleep 0.2; done
kill -TERM "$pid"
sleep 6
kill -TERM "$pid"
wait "$pid" && rc=0 || rc=$?
expect "it fails" 1 "$rc"
contains "and says the migrations go on without the lock" "migrations go on without the backup lock" "$(cat "$root/up_twice.log")"

echo "-- interrupted before the backfill wrote its pid, with a stale pid file from an earlier run"
setup stale_pid
echo slow > "$STUB_STATE/backfill"
echo 3 > "$STUB_STATE/pid_delay"
sleep 300 & stale=$! # a live process that is not the backfill
echo "$stale" > "$STUB_CTR/tmp/package-backfill.pid"
FLEET_BACKFILL_UP_WAIT=60 "$script" > "$root/stale_pid.log" 2>&1 & pid=$!
for _ in $(seq 1 50); do grep -q "moving the package lists" "$root/stale_pid.log" && break; sleep 0.2; done
kill -TERM "$pid"
wait "$pid" || true
expect "the stale pid was not signalled" yes "$(kill -0 "$stale" 2> /dev/null && echo yes || echo no)"
kill "$stale" 2> /dev/null || true
contains "it waited for this run's backfill and stopped it" "backfill interrupted" "$(cat "$STUB_STATE/events")"
contains "and says so" "the backfill stopped" "$(cat "$root/stale_pid.log")"

echo "-- /up never answers"
setup timeout
echo 1000 > "$STUB_STATE/up_after"
out="$(run 1)"
contains "it gives up and says the migrations may still run" "though its migrations may still run" "$out"

exit "$failed"
