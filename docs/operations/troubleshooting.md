# Troubleshooting

Start with the two logs: the agent's on the VM (`journalctl -u fleet-agent -n 50`) and the server's (`docker logs --since 1h fleet-cmdb` on the server VM). Every API error the agent logs carries a `request_id`; search the server log for it to see the server's side of the same request ([health-and-jobs.md](health-and-jobs.md#logs)).

## The deploy fails

Open the failed run in **Actions > Deploy**. The first error line names the problem.

- **`set the variable …` or `set the secret …`:** that setting is missing from the `production` environment. Add it as the kind the message names ([install-server.md](install-server.md#2-create-the-github-environment)), then run the workflow again.
- **A warning that a setting `is set as a secret, which the deploy does not read`:** `FLEET_RELEASE_KEY_CURRENT`, `FLEET_RELEASE_KEY_NEXT`, `FLEET_DASHBOARD_HOST`, and `FLEET_AGENT_HOST` are variables. Delete the secret, add a variable with the same name, and run the workflow again.
- **`… holds a line break`:** a variable has more than one line. For a release key, use only the second line of the `.pub` file.
- **A `git` error, such as `not a git repository`:** the runner has no `git`, and an older `cd.yml` needed it. The current workflow does not. Deploy from the newest `main`.
- **`FLEET_TLS_CERT is not signed by a certificate authority agents trust`:** the secret does not hold a Cloudflare Origin CA certificate, or holds the key instead. Copy the **Origin Certificate** again, from `-----BEGIN CERTIFICATE-----` to `-----END CERTIFICATE-----`.
- **`the Docker network … does not exist`:** start the PostgreSQL container first, or fix `FLEET_DB_NETWORK`.
- **`the app did not answer /up` or `does not answer HTTPS on 3443`:** the log printed after it says why. The usual causes are a key that does not match the certificate, a certificate without `FLEET_AGENT_HOST` in it, or a wrong `DATABASE_PASSWORD`.
- **The run is skipped:** it was started from a branch other than `main`. Only `main` deploys.
- **`lingering is off for deploy`** (in **Set up backups on the server**): run `loginctl enable-linger deploy` on the VM as root once, then run the workflow again. The app was not replaced.
- **`a restore is in progress`:** `docker.sh restore` is running on the VM; the app was not replaced. Deploy when it has finished.
- **`still busy after 20 minutes`:** a backup or the restore drill has held the backup lock for over 20 minutes, and the deploy does not replace the app meanwhile (its migrations would queue behind `pg_dump`'s locks). Run the workflow again later, or after the drill.
- **`a restore of … did not finish`:** a restore failed or was killed; the app was not replaced. Finish it as backup-and-restore.md's "Restore" says, then deploy.

## Imports are refused: no release key

The **Agents** page says **No release key is configured**, and every import is refused. The server reads the release keys from the `production` environment's **variables**, never from its secrets.

1. In **Settings > Environments > production**, delete any secret named `FLEET_RELEASE_KEY_CURRENT` or `FLEET_RELEASE_KEY_NEXT`.
2. Add `FLEET_RELEASE_KEY_CURRENT` as a **variable**. Its value is the second line of `agent/release-keys/current.pub`, the one that starts with `RW`.
3. Run **Actions > Deploy**. The Agents page no longer shows the notice. Import the release again.

## The agent hostname certificate is not trusted

The installer stops with `presented a certificate this VM does not trust`, or the agent logs TLS errors and the host goes offline.

1. **Is the VM's clock right?** `timedatectl`: a clock far off makes every certificate look invalid. Fix time synchronisation first.
2. **Which certificate does the server present?**

   ```sh
   echo | openssl s_client -connect fleet-vm.example.com:443 -servername fleet-vm.example.com 2>/dev/null \
     | openssl x509 -noout -subject -issuer -enddate -ext subjectAltName
   ```

   - Issuer `CloudFlare Origin SSL ...`, the internal hostname in `subjectAltName`, and a future `notAfter`: the certificate is right ([ADR 0024](../decisions/0024-cloudflare-origin-ca-for-the-server.md)). Then the agent is too old to trust it: agents trust Cloudflare's Origin CA from the first release that includes `agent/trust`. Install a current release.
   - An expired `notAfter`: renew the certificate ([install-server.md](install-server.md#7-upgrade-change-a-setting-roll-back)); the Settings page also says so.
   - No certificate at all, or the connection is refused: the server is not serving HTTPS. `docker logs fleet-cmdb` says why it did not start (a key that does not match, or a certificate for another name).
3. **Is the name pointing at the server?** `getent hosts fleet-vm.example.com` on the VM must give the server's address. A different address means the internal DNS record is missing or the VM uses another resolver.

Only for a private certificate authority (not the default setup): pass `--ca-file ca.pem` to the installer.

## The dashboard does not open through the tunnel

Cloudflare shows an error page for `fleet.example.com`.

- **`502` or `Bad gateway`:** the tunnel VM cannot reach `https://fleet-vm.example.com`. From the tunnel VM, `curl -sk -o /dev/null -w '%{http_code}\n' -H 'Host: fleet.example.com' https://fleet-vm.example.com/sign_in` should print `200` (`-k`: curl does not know Cloudflare's Origin CA; the tunnel does). If it does not connect, check `docker ps --filter name=fleet-cmdb` on the server, that the name resolves on the tunnel VM, and the firewall rule (it must allow the tunnel VM). A certificate error in the tunnel's log means **No TLS Verify** is off as it should be, but the certificate is not for `fleet-vm.example.com` or has expired.
- **An empty `404`:** the request did not carry the dashboard hostname. Leave **HTTP Host Header** empty in the tunnel's public hostname, and check that `FLEET_DASHBOARD_HOST` matches it.

## The agent gets `401`

The agent logs `the server rejected this agent's credential (it may have been revoked, or the host retired)`. The credential is unknown to the server: the host was revoked or retired, it was re-enrolled from another machine, or the config was copied from another VM. The host page shows which. Re-enroll the VM ([fleet-operations.md](fleet-operations.md#re-enroll-a-host-new-credential)); for a retired host, enroll it as a new host instead. The agent retries about every 30 minutes and recovers on its own once re-enrolled with `fleet-agent install --reenroll`.

`403 reenrollment_required` means a re-enrollment was started for the host; finish it on the VM with the command the dashboard showed.

## VMs cloned from one template

VMs cloned from one template all have the same machine ID (`/etc/machine-id`), unless the template was prepared for cloning. The approval page then says the new VM has the same machine ID as a host you already have.

- **When you approve,** choose **A new host**. It is the default when the hostnames differ. Choosing the existing host instead re-enrolls it: the new VM takes over that host, and the old VM's agent stops working.
- **Give each clone its own machine ID,** before installing the agent if you can. On the clone, as root:

  ```sh
  old=$(cat /etc/machine-id)
  rm -f /etc/machine-id /var/lib/dbus/machine-id
  systemd-machine-id-setup
  if [ -d /var/lib/dbus ]; then ln -s /etc/machine-id /var/lib/dbus/machine-id; fi
  [ "$(cat /etc/machine-id)" != "$old" ] && echo "new machine ID"
  ```

  Remove both files: `systemd-machine-id-setup` does nothing while `/etc/machine-id` is there, and copies the old ID back from `/var/lib/dbus/machine-id` if that file holds it.
- **If the agent is already installed,** restart it (`systemctl restart fleet-agent`). The host page then warns that the credential was used from another machine. To clear it, re-enroll the VM: `fleet-agent install --reenroll`, and approve it as a re-enrollment of the same host.
- **To fix the template,** empty its machine ID just before you shut it down for the last time: `truncate -s 0 /etc/machine-id`, then `rm -f /var/lib/dbus/machine-id` and, if `/var/lib/dbus` exists, `ln -s /etc/machine-id /var/lib/dbus/machine-id`. Each clone then makes its own ID when it first boots.

## The clock is off

The agent logs `this host's clock differs from the server's`. The server always uses its own clock for liveness and audit times, so a wrong VM clock does not make a host look offline, but report timestamps are off and, if it is far off, TLS fails (above). Enable time synchronisation on the VM (`timedatectl set-ntp true`; check `timedatectl` shows `System clock synchronized: yes`). The agent logs `this host's clock agrees with the server's again` once fixed. Check the server's clock the same way.

## A host stays offline

1. On the VM: `systemctl status fleet-agent`. If it is not running, `journalctl -u fleet-agent -n 50` says why (often a config error, exit code 78, which names the key at fault). If it runs but keeps restarting (`systemctl show fleet-agent -p NRestarts` grows, or the host shows **Recovering**), check whether it is being killed at its memory limit ([below](#the-agent-was-killed-for-using-too-much-memory)).
2. If it is running, its log shows whether requests fail: `cannot reach the fleet server` is a network, DNS, or certificate problem (above); `401` is a credential problem (above); `the server is rate limiting this agent` is the server's own limit (a minute at most), which resolves itself. `too many requests (429), but not the fleet server's own rate limit (perhaps a proxy or load balancer in front of it)` comes from something in front of the server, and may not resolve itself (a misconfigured edge limit, for example): check the rate limits of the proxy, load balancer, or CDN on the agent hostname. Meanwhile the agent keeps retrying with its normal backoff, at most 5 minutes apart, and ignores that answer's `Retry-After`. To have agents wait out an edge limit instead, see [scaling.md](scaling.md) ("Rate limit at the edge").
3. On the server: `docker exec fleet-cmdb curl -s http://localhost:3000/health`. If `job_liveness` is `failing`, the liveness evaluation is not running, so no host's status changes: check `docker ps --filter name=fleet-cmdb` and `docker logs fleet-cmdb` (or `docker logs fleet-cmdb-jobs` with `FLEET_JOBS_CONTAINER=true`) on the server, and the failed jobs page. If the jobs container keeps restarting or the deploy said its workers did not start, no background job runs at all: fix what its log says, or set `FLEET_JOBS_CONTAINER=false` and run the Deploy workflow again, which goes back to one container with the jobs inside.

## The agent was killed for using too much memory

The agent's unit caps its memory at 128 MiB and its threads and processes at 64 (#182). It needs about 8 MiB at rest, and about 81 MiB at most on a host with 20,000 packages (most of it `dpkg-query`'s; the agent runs one listing at a time). If it reaches 128 MiB, the kernel kills it in its own cgroup and systemd restarts it 10 seconds later. A slow leak, or a host with too many packages, shows only as restarts: the host stays online (a heartbeat goes out at every start), but sends no package report, and `systemctl show fleet-agent -p NRestarts` keeps growing. The server does not show those restarts yet (#251). So look here when a host is online but its package report is missing or old. If the kills come at four starts within five minutes, systemd stops restarting it, and the agent goes into recovery mode. The host then shows **Recovering**, with the reason `fleet-agent.service kept failing and systemd stopped restarting it (oom-kill, last exit killed KILL)`, or `(signal, last exit killed KILL)`.

1. **See it in the journal:**

   ```sh
   journalctl -u fleet-agent -u fleet-agent-recovery --since "1 day ago" | grep -iE 'oom|killed|start-limit'
   journalctl -k --since "1 day ago" | grep -i 'memory cgroup out of memory'
   systemctl show fleet-agent -p NRestarts -p Result -p MemoryPeak -p MemoryMax -p TasksMax
   ```

   The kernel's `Memory cgroup out of memory: Killed process ...` line, with `oom_memcg=/system.slice/fleet-agent.service` just before it, is the reliable sign of the memory limit, and names the process it killed: `fleet-agent`, or its `dpkg-query` on a host with very many packages. systemd's own lines vary: `A process of this unit has been killed by the OOM killer` and `Failed with result 'oom-kill'`, or only `Failed with result 'signal'` with status `KILL` when the agent itself was killed and systemd saw its exit first. `Resource temporarily unavailable (os error 11)` in the agent's own lines, when it starts a program or a thread, means the task limit. (`MemoryPeak` needs systemd 256 or later, as in Debian 13; on older systemd read `/sys/fs/cgroup/system.slice/fleet-agent.service/memory.peak`.)

2. **Count the packages** (`dpkg-query -W | wc -l`). Below 20,000, the agent should never come near the limit: this is a bug, most likely a leak in the release it runs. Report it with the journal lines, and roll out a fixed release when there is one; recovery mode keeps the host reachable for it meanwhile. Above about 35,000, `dpkg-query` itself needs more than the limit allows, so every listing is killed. The agent is then restarted every few minutes (after a restart, the package report waits a random 0 to 10 minutes) and seldom reaches recovery mode, so the host looks online with no package report. Raise the limit (next step).

3. **Raise the limit with a drop-in**, never in the unit file, which the installer replaces:

   ```sh
   sudo systemctl edit fleet-agent
   ```

   and add, between the comment lines:

   ```ini
   [Service]
   MemoryMax=256M
   ```

   (`TasksMax=128` for the task limit; `MemoryMax=infinity` removes the memory limit.) For recovery mode, do the same with `sudo systemctl edit fleet-agent-recovery`. Then start the agent again:

   ```sh
   sudo systemctl reset-failed fleet-agent && sudo systemctl start fleet-agent
   systemctl show fleet-agent -p MemoryMax -p TasksMax   # the new values, in bytes
   ```

   Recovery mode sees the service running and exits by itself. The drop-in stays across updates, re-installs, and unit refreshes. `sudo systemctl revert fleet-agent` removes it.

**`MemoryMax=infinity` on a VM you did not change** means its units are older than #182. The installer writes the limits, and so does a confirmed update from a release that refreshes the units (#232); an update from an older release does not. If the installed version has the limits, `sudo fleet-agent install --refresh-units` writes its units; otherwise run the installer of the current release ([install-agent.md](install-agent.md#by-hand-on-one-vm)).

## The onboarding request expired

The installer stops with `the onboarding request expired before an operator approved it; nothing was enrolled` (exit code 5). Nothing was created on the server. Run the same install command again for a new code, and approve it within 10 minutes (`FLEET_ONBOARDING_TTL_MINUTES`). If the approval page says the code is unknown, it was mistyped, already decided, or expired: start again. If the installer refuses to start with too many waiting requests, approve or reject the pending ones on the approval page first. If it says a proxy, load balancer, or CDN in front of the server refused a request as too many requests (HTTP 429), the server never saw it: check that device's rate limits on the agent hostname. While waiting for approval, such answers are retried (with one warning) until the request expires.

## A rollout halted

A rollout halts when any host reports `failed` or `rolled_back`, or when a host sent the update has not reported within 30 minutes (`unconfirmed`). It then offers the update to no further host until an operator resumes or cancels it ([install-agent.md](install-agent.md#remotely-in-a-rollout)).

1. Read why: the **Agents** page shows the halted rollout with its reason, and each host's result. The audit log has the `update.*` and `rollout.*` entries.
2. For each host that did not succeed, read its log on the VM: `journalctl -u fleet-agent | grep -i update`. `failed` means the update was refused before anything changed (a download, signature, checksum, free-space, or self-test failure: the reason says which); the VM still runs the old version.
3. `unconfirmed` usually means the host was offline or could not reach the release download; once it is back, it reports, and the result is recorded.
4. Fix the cause, then choose **Resume** on the Agents page. If the release itself is bad, choose **Cancel rollout** and publish a fixed, newer release; never try to push an older one.

## An update was rolled back

The host's update history and the audit log show `rolled_back` with a reason, and the VM runs the previous version again. The agent rolls back when the new version does not get a heartbeat accepted within 5 minutes, when its service fails to start or keeps failing, or when the VM restarts during the update. On the VM:

```sh
journalctl -u fleet-agent -u fleet-agent-update -u fleet-agent-rollback --since "1 hour ago"
fleet-agent --version                     # the version it rolled back to
cat /var/lib/fleet-agent/update-result.json   # only until the server has accepted the result
```

The new version's own log lines, before the rollback, say why it did not confirm: often it could not reach the server, or a config option it does not accept. Fix that and run a new rollout, or upgrade that VM by hand ([install-agent.md](install-agent.md#by-hand-on-one-vm)).

## A host shows "Recovery mode is not set up"

The host's agent reports that systemd does not run its recovery unit ([ADR 0030](../decisions/0030-agent-recovery-mode.md)): if it keeps failing on a version it has confirmed, it stops until someone starts it on the VM. The Fleet page's **Recovery mode: Not set up** filter lists every such host. On the VM:

```sh
head -n 1 /etc/systemd/system/fleet-agent.service /etc/systemd/system/fleet-agent-recovery.service
systemctl show -p OnFailure -p NeedDaemonReload fleet-agent   # names fleet-agent-recovery.service; NeedDaemonReload=no
journalctl -u fleet-agent-update | grep -i units   # the last update's refresh
```

- **Units from an older release, or not reloaded:** `sudo fleet-agent install --refresh-units` writes the installed version's units and reloads systemd. An update from an older agent release does not refresh them; the update after it does.
- **It refuses with "cannot check the units before writing them: /usr/bin/systemd-analyze is missing":** this VM has no `systemd-analyze`, so the units cannot be checked, and are not written without the check. Nothing was changed. Install it (it ships with systemd; some distributions package it separately) and run `sudo fleet-agent install --refresh-units` again, or re-run `sudo fleet-agent install`, which writes the units and restarts the service under them.
- **It refuses with "systemd would not load this version's units":** the release's units do not suit this VM's systemd. Nothing was changed; the old units keep running the agent. Report it with the `systemd-analyze verify` output it shows.
- **A unit file without the first line `` # Written by `fleet-agent install` ``:** someone replaced it by hand, and the agent never overwrites it. Move it away, keep local changes in a drop-in (`systemctl edit fleet-agent`), and run `sudo fleet-agent install --refresh-units`.
- **A note in the update history** ("its systemd units were not installed"): the update succeeded but the refresh did not; the note says why.
- **"does not report"**: the agent is older than the release that reports it, and its own release has no recovery mode, so its installer cannot set it up. Update it from the Agents page; after that first update, `sudo fleet-agent install --refresh-units` (or the next update) sets it up.


## A host shows "Recovery mode could not be checked"

The agent could not tell whether systemd runs its recovery unit: `systemctl show` failed (for example a D-Bus error, or an answer without the expected properties) or did not answer within 10 s, or `/etc/systemd/system/fleet-agent-recovery.service` could not be read (for example it is not a regular file). Recovery mode may still be set up, and `--refresh-units` does not fix this. On the VM:

```sh
journalctl -u fleet-agent | grep "cannot tell whether recovery mode"   # the reason, logged once
systemctl show -p OnFailure fleet-agent                                 # does systemd answer?
ls -l /etc/systemd/system/fleet-agent-recovery.service
```

Fix the cause (a busy or stuck systemd, or something other than a regular file in place of the unit). The next heartbeat checks again.

## Package updates succeed, but vulnerabilities stay open

**Apply package updates** succeeds, yet the host's **Vulnerabilities** tab still lists findings with a fixed version. Debian publishes most security fixes in its security repository. If the VM's APT sources leave it out, `apt-get upgrade` never sees those fixes. VMs built from a minimal template often lack it.

1. On the VM, check that the repository is there:

   ```sh
   apt-cache policy | grep -- -security     # should list trixie-security
   ```

2. If nothing is listed, add it. On Debian 13, in `/etc/apt/sources.list.d/debian.sources`:

   ```
   Types: deb
   URIs: http://security.debian.org/debian-security
   Suites: trixie-security
   Components: main
   Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
   ```

3. Run **Apply package updates** on the host again. Its package report follows, and the fixed findings close.
4. If some stay open, the fix may be held back. The task respects holds, installs no new packages, and removes none, so a fix that needs a new dependency is left alone. On the VM:

   ```sh
   apt-mark showhold                         # packages you have held
   apt-get -s upgrade | grep -A20 'kept back' # fixes that need a new or removed package
   ```

   Install those by hand (`apt-get install <package>`) once you have checked what they change.

## The package database needs repair

**Apply package updates** timed out, failed during the upgrade, or failed at once with `dpkg was interrupted` in its output, and the task page (when it timed out) or its output (when it failed) says the package database may need repair. dpkg was stopped part-way, so some packages are unpacked but not configured (`half-configured`, `half-installed`, `unpacked`). The agent never repairs it itself (ADR 0016): it is a job for root on the console. Until it is repaired, every new **Apply package updates** fails with `nonzero_exit`, and the agent's package report names those packages as skipped (the host's **Packages > Compare** shows them as "Skipped / incomplete", never as removed).

On the VM, as root:

1. Make sure the task has really ended, so you do not race it:

   ```sh
   systemctl list-units --all 'fleet-agent-task-*'   # nothing active; a task unit still running is still upgrading
   pgrep -a 'apt|dpkg'                                # nothing
   ```

2. See what is incomplete:

   ```sh
   dpkg --audit
   dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' | grep -v '^ii' | grep -v '^rc'
   ```

3. Finish configuring them. This runs the packages' own maintainer scripts, as the upgrade would have:

   ```sh
   DEBIAN_FRONTEND=noninteractive dpkg --configure -a
   ```

   If it hangs or fails again, the same maintainer script is the cause (often what made the task time out): `ps -ef --forest` shows which one; fix what it waits for, then run it again.
4. If apt still reports broken dependencies, look before you act: `apt-get -s -f install` shows what it would change. It may remove packages, which the task never does, so run `apt-get -f install` only if that is what you want.
5. `dpkg --audit` prints nothing when it is repaired. Then run **Apply package updates** again from the dashboard (packages upgraded before the stop stay upgraded), or **Refresh reports** to see the repaired state on the host's **Packages** and **Vulnerabilities** tabs.

If the agent was restarted while the upgrade ran, the upgrade went on in its own unit and the task reports how it ended once it has; there is nothing to repair unless that result says so ([agent-task-privileges.md](agent-task-privileges.md#agent-restarts-while-a-task-runs)).

## `/health` is unhealthy

`docker exec fleet-cmdb curl -s http://localhost:3000/health` on the server (or `curl --cacert <(cat agent/trust/*.pem) https://fleet-vm.example.com/health` from a VM on your network) names the failing check; [health-and-jobs.md](health-and-jobs.md) explains each. `backup` fails until a backup has run (the first deploy takes one), and `job_liveness` until a minute or two after a start; both are expected. `audit_guard` is `warning` until the PostgreSQL superuser has run `ops/postgres/audit-guard.sql` ([install-server.md](install-server.md)); it does not make `/health` 503. If `backup` stays `failing`, see "Backups fail" below.

## Backups fail

`/health` reports `"backup":"failing"`, or the deploy warned that the first backup could not start. On the VM, as the deploy user, `journalctl --user -u fleet-cmdb-backup.service -n 30` shows the timer's last run (as root, `journalctl _SYSTEMD_USER_UNIT=fleet-cmdb-backup.service -n 30` if the journal is not persistent), and `~/.local/share/fleet-cmdb/backup/docker.sh backup` runs one with its messages on the terminal:

- **`… does not exist` or `… is not a mount point`:** the backup location is not mounted at `FLEET_BACKUP_DIR`. Mount it ([install-server.md](install-server.md#1-check-the-prerequisites)), or set `FLEET_BACKUP_ALLOW_LOCAL=true` if keeping the sets on the VM is acceptable, then `~/.local/share/fleet-cmdb/backup/docker.sh backup`.
- **`Permission denied`** under `/backups`: the location does not let uid 1000 write. `chown 1000:1000` it (on the file server, for NFS with root squashing).
- **`pg_dump is PostgreSQL … but the server is PostgreSQL …`:** set the variable `FLEET_BACKUP_PG_IMAGE` to `postgres:<the server's version>` and run the Deploy workflow.
- **`password authentication failed`:** `DATABASE_PASSWORD` is wrong; the app would fail too. Fix the secret and run the Deploy workflow: the backup reads the password from the app container.
- **`refused: the database holds … fewer than the newest set`:** the database is not the one that was backed up. If the server was lost (for example the empty databases of a rebuilt server), restore a set ([backup-and-restore.md](backup-and-restore.md#restore)); do not force. If you emptied the databases on purpose for a fresh start, or restored an older set on purpose and the restore did not back it up, run `docker.sh backup --force` once: that set becomes the one later backups compare against, and the earlier database's newest set is kept until you `docker.sh delete` it (its older sets age out).
- **`refused: a restore of … did not finish`:** a restore failed part-way or was interrupted. Do what the message says: with the app stopped, drop the four databases, empty the release directory, and run `docker.sh restore` again (backup-and-restore.md's "Restore"). Delete the marker it names only if you are sure the databases are complete.
- **`refused: busy with …`:** a restore, drill, deploy, or another backup holds the backup lock. Wait for it; the message names it.
- **`may not use Docker`:** the deploy user is not in the `docker` group, or its systemd instance started before it was added. Add it, then as root `systemctl restart user@$(id -u deploy).service`.
- **`there is no fleet-cmdb container`:** the backup reads the database password from the app container. Run the Deploy workflow.
- **The restore drill says `ALTER ROLE cmdb CREATEDB;`:** run that once in the PostgreSQL container as its superuser ([backup-and-restore.md](backup-and-restore.md#the-restore-drill)).
