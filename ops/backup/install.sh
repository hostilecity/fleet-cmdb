#!/usr/bin/env bash
# Installs the deployment's backup on the app's VM, as the deploy user (#138, docs/operations/backup-and-restore.md).
# The Deploy workflow (.github/workflows/cd.yml) runs it from the shipped code after each deploy:
#   - copies ops/backup to ~/.local/share/fleet-cmdb/backup, where the timer runs docker.sh from;
#   - installs the user units fleet-cmdb-backup.service and fleet-cmdb-backup.timer into ~/.config/systemd/user and
#     enables the timer (daily at 02:30, with a random delay of up to 10 minutes, caught up after a missed run);
#   - pulls the PostgreSQL client image, so its patch releases arrive (a failure only warns: the copy on the VM is
#     used, and Docker Hub being down never fails a deploy).
# It runs before the deploy replaces the app, so whatever fails here stops the deploy with the old app still running.
# It refuses while a restore runs (the backup lock, see docker.sh), or while an unfinished restore left its marker. The deploy user's systemd instance must run
# without a login: once, as root, `loginctl enable-linger <user>`. No root is needed here.
set -euo pipefail

die() { echo "backup install: $*" >&2; exit 1; }

src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="$HOME/.local/share/fleet-cmdb/backup"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
user="$(id -un)"
lock_file="$HOME/.local/state/fleet-cmdb/backup.lock"

if [ -f "$lock_file" ] && ! flock -n "$lock_file" true && [[ "$(cat "$lock_file")" == restore* ]]; then
  die "a restore is in progress ($(cat "$lock_file")): deploy when it has finished"
fi
if [ -e "$HOME/.local/state/fleet-cmdb/restore-incomplete" ]; then
  die "$(cat "$HOME/.local/state/fleet-cmdb/restore-incomplete"): finish the restore before deploying (docs/operations/backup-and-restore.md)"
fi

[ "$(loginctl show-user "$user" -p Linger --value 2> /dev/null || true)" = yes ] \
  || die "lingering is off for $user, so its backup timer would run only while it is logged in. Run this once on the VM as root: loginctl enable-linger $user"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
for _ in $(seq 1 30); do [ -S "$XDG_RUNTIME_DIR/bus" ] && break; sleep 1; done
[ -S "$XDG_RUNTIME_DIR/bus" ] || die "the systemd user instance of $user is not running ($XDG_RUNTIME_DIR/bus is missing)"

# Replace the copy whole, so a backup that starts meanwhile sees the old or the new scripts, never a mix.
mkdir -p "$(dirname "$dest")"
rm -rf "$dest.new" "$dest.old"
cp -R "$src" "$dest.new"
chmod -R u+rwX,go+rX,go-w "$dest.new" # the containers read it as uid 1000; it holds no secret
if [ -e "$dest" ]; then mv "$dest" "$dest.old"; fi
mv "$dest.new" "$dest"
rm -rf "$dest.old"

mkdir -p "$units"
install -m 0644 "$src/fleet-cmdb-backup.service" "$src/fleet-cmdb-backup.timer" "$units/"
systemctl --user daemon-reload
systemctl --user enable --now fleet-cmdb-backup.timer
systemctl --user list-timers fleet-cmdb-backup.timer --no-pager
"$dest/docker.sh" pull || true
