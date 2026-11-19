#!/usr/bin/env bash
# The upgrade step of #196 on a large database (ADR 0028, docs/operations/upgrades.md): when the server's migration
# refused at container start ("fleet-cmdb upgrade step needed"), this moves the package lists into package sets in the
# waiting app container, restarts it, and waits until it serves, all under the backup lock. Run it on the app's VM, as
# the deploy user, from the installed copy:
#
#   nohup ~/.local/share/fleet-cmdb/backup/package-backfill.sh > ~/packages-backfill.log 2>&1 &
#
# - The lock is #236's (lock.sh, as docker.sh takes it): it waits up to an hour for a running backup or drill (as a
#   backup does), refuses at once while a restore holds it, and refuses while an unfinished restore left its marker,
#   checked again once the lock is held. So no backup, drill, restore, or deploy runs meanwhile; a deploy waits for
#   it up to 20 minutes and then fails without replacing the app.
# - `bin/rails packages:backfill` is resumable: run this again after an interruption and it carries on.
# - Interrupted (Ctrl-C, or SIGTERM) during the backfill, it stops the backfill in the container (the batch in progress
#   rolls back), waits up to a minute for it to end, and exits without restarting the app: the app still waits with
#   the upgrade step, and the lock is released. If the backfill has not ended by then, it says so: a second
#   `packages:backfill` reports Busy until it does.
# - The restart re-runs the migrations, which finish the upgrade. The lock is held until the app answers /up on 3000
#   and on 3443 (up to FLEET_BACKFILL_UP_WAIT seconds, 1800 by default), so nothing that takes the lock runs while the
#   migrations do. It stops waiting at once if the container stops, restarts by itself (a crash loop under
#   --restart unless-stopped), or logs the refusal again, and says so with the log's end.
# - Interrupted while it waits for /up, it keeps waiting, and the lock, so the migrations finish alone; a second
#   interrupt stops it, and the lock is then released although they may still run.
# - After FLEET_BACKFILL_UP_WAIT without /up it releases the lock although the migrations may still run; the runbook
#   has the backup timer stopped and the Deploy workflow disabled until the app serves.
set -euo pipefail

ops="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app=fleet-cmdb
up_wait="${FLEET_BACKFILL_UP_WAIT:-1800}"
# In the container's working directory (/rails), which the app may write: the backfill's pid, to stop it. Removed
# before the backfill starts and after it ends, so a pid read from it is this run's.
pid_file=tmp/package-backfill.pid

die() { echo "fleet-cmdb package backfill: $*" >&2; exit 1; }
log() { echo "fleet-cmdb package backfill: $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }
inspect() { docker inspect -f "$1" "$app" 2> /dev/null || true; }
tail_log() { docker logs --tail 20 "$app" 2>&1 || true; }
backfill_running() { docker exec "$app" sh -c "kill -0 \"\$(cat $pid_file)\"" 2> /dev/null; }
pid_written() { docker exec "$app" test -s "$pid_file" 2> /dev/null; }

stage=start
child=""
interrupts=0
on_signal() {
  interrupts=$((interrupts + 1))
  if [ "$stage" = up ] && [ "$interrupts" = 1 ]; then
    log "interrupted: still waiting for $app's migrations, holding the backup lock; interrupt again to stop waiting (the lock is then released while they run)"
    return
  fi
  trap '' INT TERM
  case "$stage" in
    backfill)
      log "interrupted: stopping the backfill in $app (the batch in progress rolls back)"
      # The docker exec may not have written this run's pid yet.
      for _ in $(seq 1 10); do
        pid_written && break
        { [ -n "$child" ] && kill -0 "$child" 2> /dev/null; } || break
        sleep 1
      done
      pid_written || die "interrupted before the backfill in $app wrote its pid; it may still start. A second packages:backfill reports Busy while one runs. $app was not restarted. The backup lock is released."
      docker exec "$app" sh -c "kill -INT \"\$(cat $pid_file)\"" 2> /dev/null || true
      for _ in $(seq 1 60); do backfill_running || break; sleep 1; done
      [ -z "$child" ] || kill "$child" 2> /dev/null || true
      if backfill_running; then
        die "interrupted; the backfill still runs in $app (a second packages:backfill reports Busy until it ends). $app was not restarted. The backup lock is released. Run this script again once it has ended: it carries on."
      fi
      die "interrupted: the backfill stopped. $app was not restarted and still waits with the upgrade step. The backup lock is released. Run this script again to carry on."
      ;;
    up) die "interrupted again: stopped waiting for $app; its migrations go on without the backup lock. Check it: docker logs $app" ;;
    *) die "interrupted before anything was changed" ;;
  esac
}
trap on_signal INT TERM

# shellcheck source=ops/backup/lock.sh
. "$ops/lock.sh"

check_restore_marker
take_lock "package backfill" 3600
check_restore_marker
[ "$(inspect '{{.State.Running}}')" = true ] \
  || die "the $app container is not running: deploy first, so that it waits with the upgrade step (docs/operations/upgrades.md)"

log "moving the package lists into package sets (bin/rails packages:backfill)"
docker exec "$app" rm -f "$pid_file"
stage=backfill
# In the background and waited for, so a signal reaches on_signal at once rather than after the backfill.
docker exec "$app" sh -c "echo \$\$ > $pid_file && exec bin/rails packages:backfill" & child=$!
wait "$child" || die "the backfill stopped (above); run this script again to carry on"
child=""
docker exec "$app" rm -f "$pid_file"

log "restarting $app: its migrations finish the upgrade"
stage=up
started="$(date +%s)"
docker restart "$app" > /dev/null
restarts="$(inspect '{{.RestartCount}}')"
while :; do
  if docker exec "$app" curl -fsS -o /dev/null http://localhost:3000/up 2> /dev/null \
    && docker exec "$app" curl -fsSk -o /dev/null https://localhost:3443/up 2> /dev/null; then
    log "done: $app serves again. Check it: docker exec $app bin/rails packages:check_snapshots"
    exit 0
  fi
  [ "$(inspect '{{.State.Running}}')" = true ] || die "$app stopped while it started; the backup lock is released. Its log: $(tail_log)"
  if [ "$(inspect '{{.State.Restarting}}')" = true ] || [ "$(inspect '{{.RestartCount}}')" != "$restarts" ]; then
    die "$app exited and was restarted while it started (a failing migration?); the backup lock is released. Its log: $(tail_log)"
  fi
  # Not grep -q: under pipefail, its early exit could fail docker logs with SIGPIPE.
  if docker logs --since "$started" "$app" 2>&1 | grep "fleet-cmdb upgrade step needed" > /dev/null; then
    die "$app refused the upgrade again; the backup lock is released. Its log: $(tail_log)"
  fi
  [ "$(($(date +%s) - started))" -lt "$up_wait" ] \
    || die "$app did not answer /up within $up_wait seconds; the backup lock is released, though its migrations may still run. Keep the backup timer stopped and Deploy disabled until it serves. Its log: $(tail_log)"
  sleep 5
done
