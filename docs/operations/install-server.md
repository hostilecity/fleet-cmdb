# Install the server

This guide takes a clean machine to a running fleet-cmdb server: the dashboard published through a Cloudflare tunnel behind Cloudflare Access, the agent API on a private LAN hostname with a Let's Encrypt certificate, scheduled backups, and the first operator ([ADR 0005](../decisions/0005-hosting-tls-deployment.md), [P1-DEPLOY](../backlog/specs/p1-deploy.md)). Each step says what it does and how to check it worked. It takes about an hour, most of it in the Cloudflare and Google consoles.

Names used below are placeholders: replace them everywhere.

| Placeholder | What it is |
|---|---|
| `example.com` | Your domain, whose DNS is on Cloudflare |
| `fleet.example.com` | The **dashboard hostname**: public, published only through the tunnel |
| `agent.fleet.example.com` | The **agent hostname**: in the same Cloudflare zone, but resolving only on your LAN, to the server |
| `192.0.2.10` | The server machine's LAN address |
| `vm-01.example.lan` | A VM that will run the agent |
| `you@example.com` | The first operator's Google account |

The agent hostname must be a name in a domain you control on Cloudflare (not `.lan` or `.local`): Let's Encrypt issues its certificate by proving control of the domain through a DNS record, and that is what lets every VM trust it with no custom certificate authority.

```
 Operator's browser ──HTTPS──> Cloudflare (Access) ──tunnel──> cloudflared ──> app:3000   fleet.example.com
                                                                                           dashboard only
 VM agents (LAN) ─────HTTPS──> server:443  Traefik (Let's Encrypt) ──────────> app:3000   agent.fleet.example.com
                                                                                           /api/v1 and /health only
```

Rails refuses `/api/v1` on the dashboard hostname and the dashboard on the agent hostname (`cmdb/lib/middleware/host_separation.rb`), so even a misconfigured tunnel cannot expose the agent API.

## 1. Check the prerequisites

| You need | Why |
|---|---|
| A server machine on the LAN: Debian 13 on x86_64, 2 CPUs, 4 GB of memory, 20 GB of disk | Runs the stack. Another Linux works for Docker, but the backup steps assume Debian 13's PostgreSQL 17 client |
| Docker Engine with the Compose plugin, version 2.17 or later | `sudo apt install docker.io docker-compose` on Debian 13, or Docker's own packages ([docs.docker.com/engine/install/debian](https://docs.docker.com/engine/install/debian/)) |
| `git`, `curl`, `openssl`, `postgresql-client` | Getting the code, checks, generating secrets, backups: `sudo apt install git curl openssl postgresql-client` |
| A domain on Cloudflare, and a Cloudflare Zero Trust organisation (the free plan is enough) | The tunnel, Access, and the DNS challenge |
| A LAN DNS server you can add a record to (your router, Pi-hole, dnsmasq, Unbound) | The agent hostname resolves only on the LAN |
| A Google Cloud project | The OAuth client for operator sign-in |
| An off-machine backup location you can mount (NFS or SMB share) | Backups ([backup-and-restore.md](backup-and-restore.md)) |
| The release public keys (`agent/release-keys/current.pub` and `next.pub` in the repository, once the owner has generated them) | The server installs only signed agent releases ([docs/releases.md](../releases.md)) |

**Network:** the server needs outbound HTTPS (443) to Cloudflare, Let's Encrypt, Docker Hub, and, to import releases from GitHub, `github.com` and GitHub's release download host (`release-assets.githubusercontent.com`; see [configuration.md](configuration.md#outbound-access)). The tunnel also needs outbound port 7844 (TCP and UDP) to Cloudflare. Inbound, only VMs on the LAN need to reach port 443 of the server. **Do not forward any port from the internet**: the dashboard arrives through the tunnel, which the server dials out to.

Check Docker works:

```sh
sudo docker run --rm hello-world     # prints "Hello from Docker!"
docker compose version               # 2.17 or later
```

## 2. Get the code

```sh
sudo git clone https://github.com/hostilecity/fleet-cmdb.git /opt/fleet-cmdb
cd /opt/fleet-cmdb
git log -1 --oneline                 # shows the commit you are about to run
```

Everything below runs from `/opt/fleet-cmdb`. The backup units expect the code there.

## 3. Create the Cloudflare DNS token (for the agent certificate)

Traefik, the TLS proxy for the agent hostname, proves to Let's Encrypt that you control `agent.fleet.example.com` by creating a temporary `_acme-challenge` TXT record through the Cloudflare API. Give it a token that can do only that.

1. In the Cloudflare dashboard: **My Profile > API Tokens > Create Token > Create Custom Token**.
2. Permissions: **Zone > Zone > Read** and **Zone > DNS > Edit**.
3. Zone Resources: **Include > Specific zone > example.com**. No other zone.
4. Create it and copy the token. It is a secret: it goes only into `.env` (step 7) and your password manager.

**Check:** the token is active (the token is read from the prompt, so it stays out of your shell history):

```sh
read -rs CF_TOKEN && curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify; unset CF_TOKEN
# {"result":{"id":"…","status":"active"},"success":true,…}
```

## 4. Create the tunnel and the Access application (for the dashboard)

**The tunnel** carries dashboard traffic from Cloudflare to the server, which dials out, so nothing is opened on your router.

1. In **Cloudflare Zero Trust > Networks > Tunnels**, create a tunnel of type **Cloudflared**, named for example `fleet-cmdb`.
2. On the install page, choose **Docker** and copy only the token: the long value after `--token`. It is a secret; it goes into `.env`.
3. Add **one public hostname**: subdomain `fleet`, domain `example.com`, path empty, service type **HTTP**, URL **`app:3000`** (the app container, as seen from the `cloudflared` container).

That one public hostname is the whole tunnel configuration. **Never add the agent hostname to the tunnel, never add a path rule for `/api`, and never add a catch-all rule that sends other hostnames to the app.** Keep the tunnel's catch-all at its default, `http_status:404`. If someone did add the agent hostname, Rails would still refuse the dashboard there, but the agent API would be reachable from the internet; the check in step 9 catches it.

**The Access application** puts Cloudflare's sign-in in front of the dashboard, so the server sees only requests from people you allowed.

1. In **Zero Trust > Access > Applications**, add a **Self-hosted** application for `fleet.example.com` (no path).
2. Add a policy: action **Allow**, include **Emails**: the operators' addresses (`you@example.com`). Add an identity provider (Google, or the one-time PIN by email) under **Settings > Authentication** if you have none.
3. A session duration of 24 hours is reasonable.

Access is the outer gate; the app then requires its own Google sign-in from an allowlisted, verified address (step 10), so both have to agree.

## 5. Create the Google OAuth client (for operator sign-in)

1. In the Google Cloud console: **APIs & Services > OAuth consent screen**. User type **Internal** if you use Google Workspace, otherwise **External** with your operators as test users. Scopes: `openid`, `email`, `profile`.
2. **APIs & Services > Credentials > Create credentials > OAuth client ID**, type **Web application**.
3. Authorised redirect URI: **`https://fleet.example.com/auth/google_oauth2/callback`**. No JavaScript origins are needed.
4. Copy the client ID and the client secret into `.env` (step 7).

## 6. Point the agent hostname at the server on your LAN

Add one DNS record **on your LAN's DNS server**, not in Cloudflare's public DNS: `agent.fleet.example.com` → `192.0.2.10` (type A). How depends on your DNS server: on Pi-hole, **Local DNS > DNS Records**; with dnsmasq, `address=/agent.fleet.example.com/192.0.2.10`; on most routers, a "static DNS" or "host override" entry.

Keeping it out of public DNS means the LAN address is not published and the name cannot be reached from outside. The certificate does not need a public A record: the DNS challenge uses only a TXT record, which Traefik creates and removes in Cloudflare.

**Check** from a VM on the LAN, and from outside:

```sh
getent hosts agent.fleet.example.com          # on vm-01.example.lan: 192.0.2.10  agent.fleet.example.com
dig +short agent.fleet.example.com @1.1.1.1   # public DNS: prints nothing
```

## 7. Write the configuration

```sh
cd /opt/fleet-cmdb
sudo cp .env.example .env
sudo chmod 600 .env
openssl rand -hex 64      # for SECRET_KEY_BASE
openssl rand -hex 24      # for CMDB_DATABASE_PASSWORD
sudo editor .env
```

Fill in every uncommented value: the two hostnames, the two generated secrets, the Google client ID and secret, the Cloudflare DNS token and tunnel token, and an email address for Let's Encrypt. Set `FLEET_RELEASE_KEY_CURRENT` (and `FLEET_RELEASE_KEY_NEXT` if there is one) to the **second line** of `agent/release-keys/current.pub` (and `next.pub`); without a current key no agent release can be imported, so no agent can be installed. Leave everything else commented out unless you have a reason: [configuration.md](configuration.md) explains every setting and its default.

`.env` now holds every secret of the installation. Copy it to your password manager or encrypted store now: a restore needs it ([backup-and-restore.md](backup-and-restore.md#what-is-backed-up)).

**Check:**

```sh
sudo docker compose config --quiet && echo "configuration complete"
```

It prints `configuration complete`, or names the first required setting that is missing (for example `required variable FLEET_AGENT_HOST is missing a value: set FLEET_AGENT_HOST in .env`).

## 8. Create the data directories and start the stack

All persistent data lives under `/var/lib/fleet-cmdb` (`FLEET_DATA_DIR`):

```sh
sudo install -d -m 0755 /var/lib/fleet-cmdb
sudo install -d -m 0750 -o 1000 -g 1000 /var/lib/fleet-cmdb/releases   # agent release files, written by the app (uid 1000)
sudo install -d -m 0755 /var/lib/fleet-cmdb/backup                     # the backup status file the app reads
sudo install -d -m 0700 /var/lib/fleet-cmdb/certs                      # Traefik's ACME account and certificate
```

The `postgres` directory is created by the database container on first start.

```sh
sudo docker compose up -d --build
```

What this does, in order:

1. Builds the app image from `cmdb/Dockerfile` (a few minutes the first time).
2. Starts PostgreSQL 17 (`db`), with its port on `127.0.0.1:5432` only, for the backup script.
3. Starts the app (`app`): `db:prepare` creates the four databases (`cmdb_production`, `_cache`, `_queue`, `_cable`) and runs the migrations, then Puma starts with Solid Queue inside it.
4. Once the app is healthy, starts Traefik (`traefik`), which requests the agent hostname's certificate, and the tunnel connector (`cloudflared`).

**Check:**

```sh
sudo docker compose ps
```

`db`, `app`, and `traefik` show `Up … (healthy)` and `cloudflared` shows `Up`. If the app is `starting` for more than two minutes or restarting, read its log: `sudo docker compose logs app`. Then:

```sh
sudo docker compose logs traefik | grep -iE 'acme|certificate'     # no "Unable to obtain ACME certificate" line
sudo docker compose logs cloudflared | grep -i 'registered tunnel connection'   # usually four lines
```

The first certificate takes up to a couple of minutes. A wrong DNS token shows here as an error from Cloudflare; see [troubleshooting.md](troubleshooting.md#the-agent-hostname-certificate-is-not-trusted).

## 9. Check the agent endpoint and the separation

From a **Debian VM on the LAN** (`vm-01.example.lan`), with nothing installed but `curl`:

```sh
curl -sS -X POST -H 'content-type: application/json' -d '{}' https://agent.fleet.example.com/api/v1
# {"error":{"code":"not_found","message":"…","request_id":"…"}}
```

That one answer proves the LAN DNS record, a certificate the VM trusts with only its system trust store (`curl` would refuse anything else), Traefik's routing, and the app's agent API. It is the same check the agent installer makes. To see the certificate:

```sh
echo | openssl s_client -connect agent.fleet.example.com:443 -servername agent.fleet.example.com 2>/dev/null \
  | openssl x509 -noout -issuer -enddate
# issuer=C = US, O = Let's Encrypt, CN = …   notAfter=… (about 90 days ahead)
```

The dashboard hostname must **not** serve the agent API, and the agent hostname must not be public:

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://fleet.example.com/api/v1     # from anywhere: 302 or 403, Cloudflare Access stops it
dig +short agent.fleet.example.com @1.1.1.1                                    # prints nothing
```

Then, in a browser signed in to Access, open `https://fleet.example.com/api/v1/heartbeat`: the page is empty (an empty `404` from the app), not a JSON error. And in **Zero Trust > Networks > Tunnels > fleet-cmdb > Public Hostname**, there is exactly one entry, `fleet.example.com`.

## 10. Add the first operator and sign in

There is no sign-up and no password: an operator is a Google account on the allowlist.

```sh
sudo docker compose exec app bin/rails operators:allow EMAIL=you@example.com
# Allowed you@example.com.
```

**Check:** open `https://fleet.example.com`, pass Cloudflare Access, choose **Sign in with Google** with that account, and the Fleet page opens (empty for now). `sudo docker compose exec app bin/rails operators:list` now shows when you signed in. Add or remove other operators the same way (`operators:disallow` signs them out on their next request). Every change is in the audit log.

## 11. Set up backups (do it now)

`/health` reports **unhealthy until the first backup has run**: that is deliberate, so an installation without backups never looks healthy. Follow [backup-and-restore.md, "Schedule it"](backup-and-restore.md#schedule-it), with these values in `/etc/fleet-cmdb/backup.env` for this deployment:

| Setting | Value |
|---|---|
| `BACKUP_DIR` | Where the off-machine share is mounted, for example `/mnt/fleet-cmdb-backups` (also set `BACKUP_DIR` in `.env` to the same path, for the restore drill) |
| `FLEET_RELEASES_DIR` | `/var/lib/fleet-cmdb/releases` |
| `FLEET_BACKUP_STATUS_FILE` | `/var/lib/fleet-cmdb/backup/last_success` |
| `PGHOST`, `PGUSER`, `PGPASSWORD` | `127.0.0.1`, `cmdb`, the `CMDB_DATABASE_PASSWORD` from `.env` (add `PGPORT` if you changed `FLEET_DB_PORT`) |

Run the first backup straight away (`sudo systemctl start fleet-cmdb-backup.service`), then the restore drill, which proves the backup can be restored:

```sh
cd /opt/fleet-cmdb
sudo docker compose run --rm restore-drill
# … one "ok" line per check, then: Restore drill passed.
```

The drill restores the newest backup set into a scratch database inside the stack, boots the app against it, checks hosts, audit entries, and release files, and removes the scratch data. Record the date and result in the drill record of [backup-and-restore.md](backup-and-restore.md#drill-record).

## 12. Check health and set up monitoring

```sh
curl -s https://agent.fleet.example.com/health
# {"status":"ok","checks":{"database":"ok","releases":"ok","backup":"ok","failed_jobs":"ok","job_liveness":"ok"}}
```

`job_liveness` turns `ok` within a minute or two of a start, once the recurring liveness job has run. What each check means: [health-and-jobs.md](health-and-jobs.md). Point an uptime monitor on the LAN (Uptime Kuma, for example) at `https://agent.fleet.example.com/health`, expecting status 200, **with certificate expiry notifications on**: that one monitor catches a stopped app, a failed backup, failing jobs, and a certificate that stopped renewing.

## 13. Import an agent release

Signed in, open **Agents**, enter a release version (for example `1.2.0`) under **Import a release**, and import it. The server downloads the tag `agent-v1.2.0` from GitHub, checks its signature against `FLEET_RELEASE_KEY_CURRENT`/`NEXT`, and lists it. Without internet access, upload the binary, the manifest, and the `.minisig` from the GitHub release instead.

**Check:** the release appears under **Releases**, and **Agents > Install an agent** shows the commands for it. Now install the first agent: [install-agent.md](install-agent.md).

## Where things are

| What | Where |
|---|---|
| Code and `compose.yaml` | `/opt/fleet-cmdb` |
| Configuration and secrets | `/opt/fleet-cmdb/.env` (mode 0600; a copy in your password manager) |
| Database files | `/var/lib/fleet-cmdb/postgres` |
| Agent release files | `/var/lib/fleet-cmdb/releases` |
| Backup status file | `/var/lib/fleet-cmdb/backup/last_success` |
| Agent hostname certificate | `/var/lib/fleet-cmdb/certs/acme.json` |
| Backup settings and units | `/etc/fleet-cmdb/backup.env`, `/etc/systemd/system/fleet-cmdb-backup.{service,timer}` |

## Logs

Each container logs to standard output, kept by Docker (10 MB × 5 files per container, set in `compose.yaml`):

```sh
sudo docker compose logs -f app                 # the app: one JSON object per line
sudo docker compose logs --since 1h traefik     # TLS proxy and certificate renewal
sudo docker compose logs cloudflared            # tunnel connections
sudo docker compose logs db                     # PostgreSQL
journalctl -u fleet-cmdb-backup.service         # backups
```

The app's log format, and how to trace one agent report through it: [health-and-jobs.md](health-and-jobs.md#logs). Failed background jobs are on the dashboard (**See the failed jobs** in the red banner). Agent logs are on each VM: `journalctl -u fleet-agent`.

## Certificate renewal

Traefik renews the agent hostname's certificate by itself, starting 30 days before it expires (Let's Encrypt certificates last 90 days), using the same DNS challenge. Nothing needs doing. If renewal fails, for example because the Cloudflare token was revoked:

- Traefik logs an error mentioning the ACME certificate (`sudo docker compose logs traefik | grep -i acme`) and retries;
- the uptime monitor from step 12 warns as expiry approaches;
- once the certificate expires, agents refuse the connection and their hosts go offline on the dashboard.

To check the expiry date at any time, use the `openssl` command in step 9.

## Upgrade the server

Server upgrades are database migrations plus a new image. Take a backup first: a migration cannot always be undone, and the backup is the way back.

```sh
cd /opt/fleet-cmdb
sudo systemctl start fleet-cmdb-backup.service && journalctl -u fleet-cmdb-backup.service -n 5   # a fresh backup
git log -1 --oneline                     # note the commit you are on, to come back to it
sudo git fetch origin
sudo git checkout origin/main            # or the commit or tag you chose; read the changes to .env.example first
sudo docker compose pull db traefik cloudflared   # security updates of the other images
sudo docker compose up -d --build        # rebuilds the app; db:prepare runs the new migrations on start
```

**Check:** `sudo docker compose ps` shows everything healthy again, `sudo docker compose logs app | grep -i migrat` shows the migrations that ran, and `/health` answers `ok`. Agents need nothing: they keep reporting, and the server accepts the previous agent release's reports (NFR-5).

- **If `.env.example` gained a required setting,** `docker compose up` stops and names it; add it to `.env`.
- **If the upgrade fails** and the old version must come back: `sudo git checkout <the commit you noted>`, then restore the backup you just took ([backup-and-restore.md](backup-and-restore.md#restore)), because the old code may not run on the migrated database, then `sudo docker compose up -d --build`.
- **PostgreSQL major versions** (`postgres:17` in `compose.yaml`) are never changed by an upgrade. Moving to a new major version is a backup, a new empty database directory, and a restore.
- **cloudflared** is pinned to one version in `compose.yaml`; it is updated by changing that line in the repository.

## Stop, start, uninstall

```sh
sudo docker compose stop            # stop everything; data stays
sudo docker compose start
sudo docker compose down            # remove the containers and networks; data under /var/lib/fleet-cmdb stays
```

To remove the server completely: uninstall the agents first ([install-agent.md](install-agent.md#uninstall)), take a last backup if you may want the history, then `sudo systemctl disable --now fleet-cmdb-backup.timer`, `sudo docker compose down --rmi local`, and delete `/var/lib/fleet-cmdb`, `/etc/fleet-cmdb`, and `/opt/fleet-cmdb`. In Cloudflare, delete the tunnel, the Access application, and the DNS API token; in Google Cloud, the OAuth client.
