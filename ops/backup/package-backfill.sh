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
# - The restart re-runs the migrations, which finish the upgrade. The lock is held until the app answers /up (up to
#   FLEET_BACKFILL_UP_WAIT seconds, 1800 by default), or until it stops or refuses again, so nothing that takes the
#   lock runs while the migrations do.
set -euo pipefail

ops="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app=fleet-cmdb
up_wait="${FLEET_BACKFILL_UP_WAIT:-1800}"

die() { echo "fleet-cmdb package backfill: $*" >&2; exit 1; }
log() { echo "fleet-cmdb package backfill: $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

# shellcheck source=ops/backup/lock.sh
. "$ops/lock.sh"

check_restore_marker
take_lock "package backfill" 3600
check_restore_marker
[ "$(docker inspect -f '{{.State.Running}}' "$app" 2> /dev/null || true)" = true ] \
  || die "the $app container is not running: deploy first, so that it waits with the upgrade step (docs/operations/upgrades.md)"

log "moving the package lists into package sets (bin/rails packages:backfill)"
docker exec "$app" bin/rails packages:backfill || die "the backfill stopped (above); run this script again to carry on"

log "restarting $app: its migrations finish the upgrade"
started="$(date +%s)"
docker restart "$app" > /dev/null
while :; do
  if docker exec "$app" curl -fsS -o /dev/null http://localhost:3000/up 2> /dev/null; then
    log "done: $app serves again. Check it: docker exec $app bin/rails packages:check_snapshots"
    exit 0
  fi
  [ "$(docker inspect -f '{{.State.Running}}' "$app" 2> /dev/null || true)" = true ] \
    || die "$app stopped while it started; its log: $(docker logs --tail 20 "$app" 2>&1)"
  if docker logs --since "$started" "$app" 2>&1 | grep -q "fleet-cmdb upgrade step needed"; then
    die "$app refused the upgrade again; its log: $(docker logs --tail 20 "$app" 2>&1)"
  fi
  [ "$(($(date +%s) - started))" -lt "$up_wait" ] || die "$app did not answer /up within $up_wait seconds; the lock is released. Its log: $(docker logs --tail 20 "$app" 2>&1)"
  sleep 5
done
