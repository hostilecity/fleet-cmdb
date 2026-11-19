# Install the server

The server runs as one Docker container, `fleet-cmdb`, on a VM on your network (larger fleets may run the background jobs in a second one, `fleet-cmdb-jobs`: [scaling.md](scaling.md)). It uses a PostgreSQL container that already runs there. Operators reach the dashboard through a Cloudflare tunnel whose connector runs on another VM. The tunnel and the agents both connect to the VM's internal hostname over HTTPS, with a Cloudflare Origin CA certificate the server serves itself ([ADR 0005](../decisions/0005-hosting-tls-deployment.md), [ADR 0024](../decisions/0024-cloudflare-origin-ca-for-the-server.md), [P1-DEPLOY](../backlog/specs/p1-deploy.md)). GitHub Actions deploys it (`.github/workflows/cd.yml`):

1. a self-hosted runner on the LAN connects to the VM over SSH;
2. it ships the commit, builds the image there, and replaces the container;
3. it installs the daily backup on the VM: a systemd timer of the deploy user that dumps the four databases with `pg_dump` in a throwaway `postgres:17` container on the database's network, with the release files, onto a backup location mounted on the VM ([backup-and-restore.md](backup-and-restore.md)).

You set secrets and variables in GitHub; apart from the one-time steps in step 1, nothing is edited on the VM.

```
 Operator's browser ──HTTPS──> Cloudflare (Access) ──tunnel──> cloudflared (tunnel VM) ──HTTPS──┐
                                                                                                ├──> VM:443 ──> fleet-cmdb:3443
 Agents on your VMs ──────────────────HTTPS, internal network only─────────────────────────────┘          │ Docker network
                                                                                                postgres (existing container)
```

Both connections go to the VM's internal hostname (`fleet-vm.example.com` below), so one certificate serves both. The tunnel passes the browser's hostname along, which is how the app tells a dashboard request from an agent's: the dashboard answers only on the dashboard hostname, and the agent API only on the internal one.

**Not here yet:**
- **Agents** trust the server's certificate only from the first agent release that includes Cloudflare's Origin CA roots ([agent/trust](../../agent/trust/README.md)). Install agents from that release on ([install-agent.md](install-agent.md)).

Names below are placeholders:

| Placeholder | What it is |
|---|---|
| `fleet.example.com` | The dashboard hostname, in your Cloudflare zone |
| `fleet-vm.example.com` | The VM's internal hostname, resolving to `192.0.2.10` on your network (and VPN) only. Agents, the tunnel, and the runner connect to it |
| `192.0.2.10` | The fleet-cmdb VM's address |
| `192.0.2.20` | The tunnel VM's LAN address |
| `deploy` | The user the runner logs in as on the VM |
| `postgres_default` | The PostgreSQL container's Docker network |
| `postgres` | The PostgreSQL container's name, on the VM and on that network |
| `backup-01.example.lan` | A file server for the backup sets |

## 1. Check the prerequisites

| You need | Check |
|---|---|
| The VM: Linux with Docker, port 443 free | `docker version`; `ss -ltn 'sport = :443'` prints only the header |
| The internal hostname resolves to the VM from the tunnel VM and from the VMs that will run agents | `getent hosts fleet-vm.example.com` on each prints `192.0.2.10` |
| A deploy user on the VM in the `docker` group (equivalent to root on the VM) | `ssh deploy@192.0.2.10 docker ps` works without `sudo` |
| The existing PostgreSQL container on its Docker network, reachable there as `postgres` (or another name: `FLEET_DB_HOST`), with the role `cmdb` owning `cmdb_production`, `cmdb_production_cache`, `cmdb_production_queue`, and `cmdb_production_cable` | `docker network ls` shows the network; `docker run --rm --network postgres_default postgres:17 pg_isready -h postgres` prints `accepting connections` |
| The deploy user's systemd instance runs without a login, for the backup timer | `loginctl show-user deploy -p Linger` prints `Linger=yes` (see below) |
| A backup location mounted at `/var/backups/fleet-cmdb` (or `FLEET_BACKUP_DIR`) that uid 1000 can write | `mountpoint /var/backups/fleet-cmdb` prints `is a mountpoint` (see below) |
| The role `cmdb` may create databases, for the restore drill | `docker exec postgres psql -U postgres -Atc "SELECT rolcreatedb FROM pg_roles WHERE rolname = 'cmdb'"` prints `t` (see below) |
| A self-hosted GitHub Actions runner on the LAN, registered for this repository, with `bash`, `ssh`, `tar`, and `openssl` (`git` is not needed), that can reach the VM on port 22 | **Settings > Actions > Runners** shows it **Idle** |
| A Cloudflare tunnel with its connector on the tunnel VM, and Cloudflare Access | The tunnel shows **Healthy** in Zero Trust |
| A Google Cloud project, for the operators' sign-in | |

**SSH access for the runner.** On your workstation:

```sh
ssh-keygen -t ed25519 -N '' -C fleet-cmdb-deploy -f fleet-cmdb-deploy
ssh-copy-id -i fleet-cmdb-deploy.pub deploy@fleet-vm.example.com
ssh-keyscan -H fleet-vm.example.com 2>/dev/null     # host keys for DEPLOY_KNOWN_HOSTS: compare with the VM's own first
```

The private key goes into the secret `SSH_PRIVATE_KEY`; then delete both files.

**One-time steps for backups** ([backup-and-restore.md](backup-and-restore.md)). On the VM, as root:

```sh
usermod -aG docker deploy                         # first, if not done yet: a user manager started before keeps its old groups
loginctl enable-linger deploy                     # the deploy user's timer runs without a login
mkdir -p /var/backups/fleet-cmdb
# Mount an off-machine location there, for example an NFS export of backup-01.example.lan, in /etc/fstab:
#   backup-01.example.lan:/export/fleet-cmdb  /var/backups/fleet-cmdb  nfs  defaults,_netdev  0  0
mount /var/backups/fleet-cmdb
chown 1000:1000 /var/backups/fleet-cmdb && chmod 0700 /var/backups/fleet-cmdb   # uid 1000 is the app's user in its containers
```

With NFS and root squashing, set that owner on the file server instead. If a person's account on the VM also has uid 1000, that account can read every set: give the deploy user (or nobody) uid 1000, or keep such accounts off the VM.

If the deploy user was added to `docker` after lingering started its systemd instance, restart that instance once: `systemctl restart user@$(id -u deploy).service`.

The backup refuses a directory that is not a mount point, so the sets cannot quietly land on the VM's own disk beside the database. If you accept that (for example because the whole VM is backed up elsewhere), set the variable `FLEET_BACKUP_ALLOW_LOCAL` to `true` instead of mounting. The export must let uid 1000 write (with NFS, no `all_squash` to another user).

In the PostgreSQL container, as its superuser (that container is provisioned separately; this is the only change it needs). The restore drill creates scratch databases:

```sh
docker exec postgres psql -U postgres -c 'ALTER ROLE cmdb CREATEDB;'
```

The database needs no published port: the backup reaches it on its Docker network.

**Server certificate** (ADR 0024). In the Cloudflare dashboard, open your zone, then **SSL/TLS > Origin Server > Create Certificate**:
1. Let Cloudflare generate the private key, with key type **ECC** (or RSA).
2. List **only** the internal hostname, `fleet-vm.example.com`.
3. Choose the validity. Cloudflare sends no reminders; the dashboard's Settings page shows the expiry and warns 30 days before.
4. Copy the **Origin Certificate** into the secret `FLEET_TLS_CERT` and the **Private Key** into `FLEET_TLS_KEY` (step 2). Cloudflare shows the key only once.

Browsers do not trust this certificate, but nothing reaches it from a browser: the tunnel trusts Cloudflare's Origin CA, and agents trust it from their build. Cloudflare's Origin CA roots expire on 2029-08-15; when Cloudflare publishes new ones, an agent release must carry them before the certificate is reissued ([agent/trust/README.md](../../agent/trust/README.md)).

**Google OAuth client.**
1. In the Google Cloud console, open **APIs & Services > Credentials** and create an **OAuth client ID** of type **Web application**.
2. Set the authorised redirect URI to `https://fleet.example.com/auth/google_oauth2/callback`.
3. On the consent screen, use **Internal** (Workspace) or **External** with your operators as test users. The scopes are `openid`, `email`, and `profile`. Set the privacy policy link to `https://fleet.example.com/privacy`, a public page that says what the dashboard keeps about the people who sign in.

## 2. Create the GitHub environment

In **Settings > Environments**, create **`production`**. Under **Deployment branches and tags**, allow only `main`. Add a required reviewer if every deploy should wait for your approval. Then add:

| Name | Kind | Example | What it is |
|---|---|---|---|
| `SSH_PRIVATE_KEY` | Secret | the `fleet-cmdb-deploy` file | The key the runner logs in to the VM with |
| `SECRET_KEY_BASE` | Secret | output of `openssl rand -hex 64` | Signs and encrypts session cookies; changing it signs everyone out |
| `FLEET_ENCRYPTION_KEY` | Secret | output of `openssl rand -hex 32` | Encrypts operators' second-factor keys at rest; keep a copy, since losing it means every operator sets up their second factor again |
| `DATABASE_PASSWORD` | Secret | | Password of the PostgreSQL role `cmdb` |
| `GOOGLE_CLIENT_ID` | Secret | `123456789012-abc.apps.googleusercontent.com` | The OAuth client (step 1) |
| `GOOGLE_CLIENT_SECRET` | Secret | `GOCSPX-…` | Its secret |
| `FLEET_TLS_CERT` | Secret | the Origin Certificate, PEM | The server's certificate (step 1). The deploy stops if agents would not trust it |
| `FLEET_TLS_KEY` | Secret | the Private Key, PEM | Its key. The server does not start if it does not match the certificate |
| `FLEET_ADVISORY_FEED_TOKEN` | Secret, optional | | Only for an advisory mirror that needs a bearer token |
| `DEPLOY_HOST` | Variable | `fleet-vm.example.com` | The VM, as the runner reaches it |
| `DEPLOY_USER` | Variable | `deploy` | The deploy user |
| `DEPLOY_DIR` | Variable, optional | `fleet-cmdb` (the default) | Working directory on the VM, relative to the deploy user's home; the code and env file are removed after each deploy |
| `DEPLOY_KNOWN_HOSTS` | Variable, recommended | the checked `ssh-keyscan -H` lines | The VM's SSH host keys. Unset: each deploy trusts the key the VM presents |
| `FLEET_DB_NETWORK` | Variable | `postgres_default` | The PostgreSQL container's Docker network |
| `FLEET_DB_HOST` | Variable, optional | `postgres` (the default) | The PostgreSQL container's name on it |
| `FLEET_DASHBOARD_HOST` | Variable | `fleet.example.com` | The dashboard hostname |
| `FLEET_AGENT_HOST` | Variable | `fleet-vm.example.com` | The internal hostname: agents and the tunnel connect to it, and the certificate must cover it (checked at boot) |
| `FLEET_RELEASE_KEY_CURRENT` | Variable, optional for now | `RWQ…` | Second line of `agent/release-keys/current.pub` ([docs/releases.md](../releases.md)); needed to import agent releases |
| `FLEET_RELEASE_KEY_NEXT` | Variable, optional | `RWQ…` | Second line of `next.pub` |
| `RAILS_LOG_LEVEL` | Variable, optional | `info` (the default) | |
| `FLEET_EXTRA_SETTINGS` | Variable, optional | `FLEET_SESSION_IDLE_MINUTES=60` | Any other non-secret setting of [configuration.md](configuration.md), one `NAME=value` per line |
| `FLEET_JOBS_CONTAINER` | Variable, optional | `false` (the default) | `true` runs background jobs in a second container, `fleet-cmdb-jobs`; only for larger fleets ([scaling.md](scaling.md)) |
| `FLEET_BACKUP_DIR` | Variable, optional | `/var/backups/fleet-cmdb` (the default) | Where the backup sets are kept on the VM: the mount point of the backup location |
| `FLEET_BACKUP_ALLOW_LOCAL` | Variable, optional | `false` (the default) | `true` lets backups go to a directory that is not a mount point |
| `FLEET_BACKUP_RETENTION_DAYS` | Variable, optional | `14` (the default) | Days a backup set is kept; the newest 3, and the newest set holding more than the newest one, are always kept |
| `FLEET_BACKUP_PG_IMAGE` | Variable, optional | `postgres:17` (the default) | The PostgreSQL client image for backups; its major version must be the server's or newer. May be pinned by digest (`postgres:17@sha256:…`) |
| `FLEET_BACKUP_DRILL_HOST` | Variable, optional | unset (the default) | Another PostgreSQL server on the database network for the restore drill's scratch databases, once the database is large ([backup-and-restore.md](backup-and-restore.md#the-restore-drill)) |

The backup reads the database host and password from the app container when it runs, so no secret is stored for it.

## 3. Publish the dashboard through the tunnel

In **Cloudflare Zero Trust > Networks > Tunnels**, open the tunnel whose connector runs on the tunnel VM and add a public hostname:
- subdomain `fleet`, domain `example.com`, path empty;
- service **HTTPS**, URL **`fleet-vm.example.com:443`**;
- under **Additional application settings > TLS**, leave **No TLS Verify** off and **Origin Server Name** empty (it is then the URL's hostname), and leave **HTTP Host Header** empty, so the app sees the dashboard hostname.

**Never publish the internal hostname as a public hostname, or an `/api` path.** The app refuses `/api/v1` on the dashboard hostname anyway (`cmdb/lib/middleware/host_separation.rb`).

In **Zero Trust > Access > Applications**, add a **Self-hosted** application for `fleet.example.com`, with an **Allow** policy for your operators' email addresses. Operators then pass Access and also sign in with Google as an allowlisted operator (step 5).

So that Google and anyone else can read the privacy page without passing Access, add a second **Self-hosted** application for `fleet.example.com` with the path `privacy`, and give it a **Bypass** policy for **Everyone**. The more specific path takes precedence. It is the only page the app serves without sign-in apart from the sign-in page itself.

## 4. Deploy

Open **Actions > Deploy > Run workflow**, pick branch `main` (a run from any other branch is skipped). The first run takes a few minutes, because the image builds on the VM. The log shows:
1. the commit;
2. under **Set up backups on the server**, the backup timer's next run;
3. `database network postgres_default exists` and the build;
4. `wait for /up` (the first start migrates the databases);
5. the container's status;
6. under **Take the first backup**: `the first backup started in the background` on the first deploy (`already holds sets` on later ones). A minute or two later, `/health` shows `"backup":"ok"`.

The deploy stops with a clear message if the network is missing, a required setting is not set, agents would not trust the certificate, lingering is off for the deploy user, a restore is in progress or did not finish, or a backup or the restore drill has held the backup lock for over 20 minutes; in each case before the app is replaced. A first backup that cannot start (for example because the backup location is not mounted) shows a warning, and `/health` stays `503`. Only names are printed, never values (and the certificate's names and expiry, which are not secret). The server does not start if the key does not match the certificate or the certificate does not cover `FLEET_AGENT_HOST`; `docker logs fleet-cmdb` says which. Secret values reach the VM over SSH standard input, into a mode-0600 env file for `docker run --env-file`, which is deleted once the containers have started. With `FLEET_JOBS_CONTAINER=true`, the jobs container gets a copy without the TLS certificate and key (`FLEET_TLS_*`), which only the app serves. Docker keeps them in the container's configuration (`docker inspect`), which only users in the `docker` group can read.

**Check:**
- `docker exec fleet-cmdb curl -s http://localhost:3000/health` on the VM shows `"backup":"ok"`. Then run the restore drill once and record it ([backup-and-restore.md](backup-and-restore.md#the-restore-drill)): `~/.local/share/fleet-cmdb/backup/docker.sh restore-drill` ends with `Restore drill passed.`
- Open `https://fleet.example.com` in a browser. Pass Access, and the sign-in page opens.
- From a VM on your network, with this repository's `agent/trust` files: `curl -s -o /dev/null -w '%{http_code}\n' --cacert <(cat agent/trust/*.pem) https://fleet-vm.example.com/up` prints `200`. That is the certificate check agents make.

### The audit log's guard (once, as the PostgreSQL superuser)

The audit log is append-only (FR-S.3). The app's own triggers refuse updates and deletes, but the app's role `cmdb` owns the tables, so it could still change or drop those triggers. One SQL file, run **once by the PostgreSQL superuser** after the first deploy has migrated the database, closes that ([ADR 0027](../decisions/0027-time-partitioned-history.md), "The audit log's guards"): the superuser takes ownership of the guard function, records the audit log's tables by their PostgreSQL id (so a rename cannot hide one), and adds two event triggers that refuse any command on them, other than adding a month. The app never runs as a superuser, so it cannot do this itself. It belongs with the task that provisions the PostgreSQL container.

**`cmdb` must not be a superuser, or able to become one.** A superuser can turn any guard off. So can a member of a superuser role, directly or through other roles (it can `SET ROLE` to it), a member of `pg_execute_server_program` or `pg_write_server_files` (a shell or files as the server, and from there a superuser), a member of `pg_create_subscription` (a subscription applies rows with the row guards skipped), and, before PostgreSQL 16, a role with `CREATEROLE` (it can grant itself those). The file refuses to run in any of these cases, and `/health` warns. Check, as the superuser (all should be `f`, and the second and third queries should print nothing):

```sh
docker exec postgres psql -U <superuser> -Atc "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = 'cmdb'"
docker exec postgres psql -U <superuser> -Atc "SELECT g.rolname FROM pg_roles g WHERE g.rolname IN ('pg_execute_server_program','pg_write_server_files','pg_create_subscription') AND pg_has_role('cmdb', g.oid, 'MEMBER')"
docker exec postgres psql -U <superuser> -Atc "SELECT r.rolname FROM pg_roles r WHERE r.rolsuper AND r.rolname <> 'cmdb' AND pg_has_role('cmdb', r.oid, 'MEMBER')"
```

If the container was created with `POSTGRES_USER=cmdb`, `cmdb` is its superuser: create another superuser, then `ALTER ROLE cmdb NOSUPERUSER`. Revoke any of the roles above (and any role that leads to a superuser), and `CREATEROLE`, from `cmdb`.

**The superuser must not query or change the audit tables by hand** (`SELECT ... FROM audit_entries` in psql included). `cmdb` owns them, and PostgreSQL runs the functions their indexes, statistics, and defaults name as whoever plans the query, so a function `cmdb` wrote would run as the superuser. The file below checks for that before it touches them; ad hoc queries do not. Read the audit log through the app, or connect as `cmdb`.

From a checkout of this repository, as the container's superuser whatever it is called (the official image names it `POSTGRES_USER`, `postgres` by default):

```sh
ssh deploy@192.0.2.10 "docker exec -i postgres sh -c 'psql -v ON_ERROR_STOP=1 -U \"\${POSTGRES_USER:-postgres}\" -d cmdb_production'" < ops/postgres/audit-guard.sql
```

(`postgres` is the container's name, `FLEET_DB_HOST`. If the superuser's name is not in the container's environment, list superusers with `docker exec postgres psql -U <a role you know> -Atc "SELECT rolname FROM pg_roles WHERE rolsuper"` and put it after `-U`.) It is one transaction: it installs everything or nothing, and a failure or a dropped connection leaves things as they were. It adopts nothing `cmdb` could have prepared and runs none of `cmdb`'s code: before it touches the audit tables it checks, from PostgreSQL's catalogs alone, that no index, statistics object, constraint, default, or column type on them uses a function, operator, or type other than PostgreSQL's own; it writes the guard's function bodies itself; it refuses a `fleet_audit_guard` schema it did not make, a table named `audit_entries_default` that is not its own default partition, and audit tables that carry anything but their own guards (another trigger, a disabled one, a rule, a policy, an unlogged or half-detached partition); and its one query over the entries runs as `cmdb`. The error lists what it found, for the superuser to look at; drop such objects as `cmdb`, not as the superuser. It also refuses to run as any other role, before the migration has partitioned `audit_entries`, or when `cmdb` is or can become a superuser, and it is safe to run again. Besides the event triggers it adds `audit_entries_default`, a default partition owned by the superuser that refuses every row (so the log still fails closed, and PostgreSQL refuses to detach a month concurrently), and it gives the id sequence to the superuser, with `cmdb` allowed only to take the next value and read it (the nightly `pg_dump` as `cmdb` reads it and the default partition). A trigger then gives every new entry its id from that sequence, whatever id an insert names, so no entry can repeat or choose an id. It cannot stop `cmdb` from inserting an entry with a backdated time: that is the partition key, which PostgreSQL does not let a trigger change. After the file has run, `cmdb` can no longer create an index or statistics object on the audit tables either. Run it again after a restore ([backup-and-restore.md](backup-and-restore.md)). Until it has run, the app works normally and `/health` shows `"audit_guard":"warning"`; afterwards `"ok"`. `docker exec fleet-cmdb bin/rails partitions:status` says whether it is installed.

A later migration that alters `audit_entries` or its guard function will need the superuser to disable the event triggers for it; its pull request will say so.

## 5. Add the first operator

```sh
ssh deploy@192.0.2.10
docker exec fleet-cmdb bin/rails operators:allow EMAIL=you@example.com
# Allowed you@example.com.
```

Then sign in with Google as that account. To manage other operators, see [fleet-operations.md](fleet-operations.md#manage-operators).

## 6. Logs and status

```sh
docker ps --filter name=fleet-cmdb        # Up …
docker logs -f fleet-cmdb                 # the app: one JSON object per line (health-and-jobs.md)
docker logs -f fleet-cmdb-jobs            # background jobs, only with FLEET_JOBS_CONTAINER=true
docker exec fleet-cmdb curl -s http://localhost:3000/health
systemctl --user list-timers fleet-cmdb-backup.timer   # the next backup
journalctl --user -u fleet-cmdb-backup.service -n 30   # the last backups (as root, journalctl _SYSTEMD_USER_UNIT=fleet-cmdb-backup.service if the journal is not persistent)
```

Release files and the backup status file are in the Docker volume `fleet-cmdb_storage`, which survives every deploy. The database is in your PostgreSQL container, and the backup sets in `/var/backups/fleet-cmdb`.

## 7. Upgrade, change a setting, roll back

- **Upgrade:** merge to `main`; every push to `main` deploys. Migrations run on start (`db:prepare`). A few upgrades of a large database need a step of their own, and say so in the log: [upgrades.md](upgrades.md).
- **Change a setting:** change the secret or variable in GitHub, then run the workflow.
- **Renew the certificate:** before it expires (Settings shows when), create a new Origin certificate as in step 1, replace `FLEET_TLS_CERT` and `FLEET_TLS_KEY`, and run the workflow. Agents need nothing.
- **Roll back:** if `FLEET_JOBS_CONTAINER` is `true` and you go back to a commit from before the jobs container existed, first run `docker stop -t 30 fleet-cmdb-jobs && docker rm fleet-cmdb-jobs` on the VM: that commit's workflow does not know the container and would leave it running new code beside the old app's own jobs. Then open the earlier Deploy run of the commit to go back to and choose **Re-run all jobs**; a run always deploys its own commit. GitHub re-runs only runs up to 30 days old: for an older commit, revert on `main` instead, and the push (or a manual run) deploys the revert. If the newer version migrated the database, the old code may not run on it: then restore the last backup taken before the upgrade ([backup-and-restore.md](backup-and-restore.md#restore)), which loses everything written since. To be safe, take a backup by hand before a deploy you may roll back: `~/.local/share/fleet-cmdb/backup/docker.sh backup`.
- Two deploys never overlap; a second one waits.

## 8. First steps in the dashboard

The server is up but empty. In this order:

1. **Make the first agent release.** Generate the release keys once, then run **Actions > Agent release** ([docs/releases.md](../releases.md#generating-the-keys-once-by-the-owner)). Nothing needs building on your own machine.
2. **Give the server the release key.** Set the **variable** (not a secret) `FLEET_RELEASE_KEY_CURRENT` to the second line of `agent/release-keys/current.pub`, then run **Actions > Deploy**.
3. **Import the release** on the **Agents** page, by its version.
4. **Install agents** on your VMs ([install-agent.md](install-agent.md)). VMs cloned from one template need one extra step: "VMs cloned from one template" in [troubleshooting.md](troubleshooting.md).
5. **Load the starter rules:** `docker exec fleet-cmdb bin/rails rules:import FILE=config/rules/debian-13.yml` ([cis-rules.md](cis-rules.md)).
6. **Vulnerability data** downloads every 6 hours by itself. To start now, choose **Data sources > Refresh now** ([health-and-jobs.md](health-and-jobs.md)).
7. **For tasks,** set up your second factor under **Settings > Your second factor**, and turn tasks on in each VM ([fleet-operations.md](fleet-operations.md#run-a-task)).

## Security notes

- **Port 443 is the only published port**, and only the tunnel VM and the VMs that run agents need it. Docker's published ports bypass `ufw`'s usual rules, so limit it in the `DOCKER-USER` chain (after Docker's DNAT the port is the container's, 3443), for example `iptables -I DOCKER-USER -p tcp --dport 3443 ! -s 192.0.2.0/24 -j DROP`.
- **The container runs with as little as it needs.** The app runs as uid 1000 with no Linux capabilities and cannot gain privileges (`--cap-drop ALL --security-opt no-new-privileges`). It can write only `storage/` (the volume), `tmp/`, and `log/`; its code and gems belong to root, so a compromised app process cannot change what it runs. The image has no test or development gems. Deploy CI checks each of these.
- **The dashboard through the internal hostname.** A client on your network can connect to `fleet-vm.example.com` while naming `fleet.example.com` as the host. It then reaches the dashboard without passing Cloudflare Access; Google sign-in and the operator allowlist still apply.
- **This repository is public, and the runner is self-hosted.** A pull request from a fork runs its own workflows and could ask for `runs-on: self-hosted`, which would run code on your LAN.
  - In **Settings > Actions > General**, require approval for fork pull request workflows from **all outside collaborators**.
  - If the repository belongs to an organisation, put the runner in a runner group limited to this repository and to `.github/workflows/cd.yml` on `main`.
  - The production secrets are out of a fork's reach, because only `main` may use the environment.

## Uninstall

```sh
systemctl --user disable --now fleet-cmdb-backup.timer
rm -rf ~/.config/systemd/user/fleet-cmdb-backup.* ~/.local/share/fleet-cmdb ~/.config/fleet-cmdb   # the backup's scripts and settings
docker rm -f fleet-cmdb-jobs fleet-cmdb    # the jobs container exists only with FLEET_JOBS_CONTAINER=true
docker volume rm fleet-cmdb_storage       # deletes uploaded release files
docker image rm $(docker images -q fleet-cmdb)
```

Then remove the tunnel's public hostname and the Access applications in Cloudflare, revoke the Origin certificate (**SSL/TLS > Origin Server**), the OAuth client in Google Cloud, and the `production` environment in GitHub. The databases stay in your PostgreSQL container, and the backup sets in the backup location. As root, `loginctl disable-linger deploy` if nothing else needs it.
