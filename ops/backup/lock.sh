# shellcheck shell=bash
# The backup lock and the restore marker (#138, #236), sourced by docker.sh and package-backfill.sh so every script that
# takes the lock does it the same way: one file, ~/.local/state/fleet-cmdb/backup.lock, held with an exclusive flock on
# file descriptor 9 for the life of the script, and a holder line written once it is held. ops/deploy/deploy.sh and
# install.sh follow the same rules. The caller defines log and die.
lock_file="$HOME/.local/state/fleet-cmdb/backup.lock"
restore_marker="$HOME/.local/state/fleet-cmdb/restore-incomplete"

# The lock shared with the deploy. $1: what is running; $2: seconds to wait for another holder (0: refuse at once).
# A restore is never waited for: whatever wants the lock refuses while one runs.
take_lock() {
  local holder
  mkdir -p "$(dirname "$lock_file")"
  exec 9>> "$lock_file"
  if ! flock -n 9; then
    holder="$(cat "$lock_file" 2> /dev/null || true)"
    if [ "$2" -gt 0 ] && [[ "$holder" != restore* ]]; then
      log "waiting for: $holder"
      flock -w "$2" 9 || die "still busy after $2 seconds: $holder ($lock_file)"
    else
      die "refused: busy with $holder ($lock_file)"
    fi
  fi
  printf '%s since %s, pid %s\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" > "$lock_file"
}

# A restore that did not finish leaves the databases and the volume in an unknown state.
check_restore_marker() {
  [ ! -e "$restore_marker" ] || die "refused: $(cat "$restore_marker")"
}
