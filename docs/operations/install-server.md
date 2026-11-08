# Install the server

This guide takes a clean machine to a running fleet-cmdb server: the dashboard published through a Cloudflare tunnel behind Cloudflare Access, the agent API on a private LAN hostname with a Let's Encrypt certificate, scheduled backups, and the first operator ([ADR 0005](../decisions/0005-hosting-tls-deployment.md), [P1-DEPLOY](../backlog/specs/p1-deploy.md)). Each step says what it does and how to check it worked. It takes about an hour, most of it in the Cloudflare and Google consoles.

There are two layouts. Both keep the agent API on the private hostname behind Traefik and the dashboard behind the Cloudflare tunnel and Access; they differ in where PostgreSQL and the tunnel connector run, and in who runs `docker compose`.

| Layout | PostgreSQL and the tunnel connector | Deployed by | Follow |
|---|---|---|---|
| **All-in-one** | Containers of this stack, on the server (`compose.yaml` + `compose.bundled.yaml`) | You, with `docker compose` on the server | Steps 1 to 13 below |
| **Existing PostgreSQL, tunnel elsewhere** | A PostgreSQL container from another Compose project on the server, and `cloudflared` on another machine on the LAN (`compose.yaml` only) | `.github/workflows/deploy.yml` on a self-hosted runner, with the settings in a GitHub environment | [Existing PostgreSQL and a tunnel on another machine, deployed by GitHub Actions](#existing-postgresql-and-a-tunnel-on-another-machine-deployed-by-github-actions) |

Names used below are placeholders: replace them everywhere.

| Placeholder | What it is |
|---|---|
| `example.com` | Your domain, whose DNS is on Cloudflare |
| `fleet.example.com` | The **dashboard hostname**: public, published only through the tunnel |
| `agent.fleet.example.com` | The **agent hostname**: in the same Cloudflare zone, but resolving only on your LAN, to the server |
| `192.0.2.10` | The server machine's LAN address |
| `192.0.2.20` | The LAN address of the machine running the tunnel connector, in the second layout |
| `vm-01.example.lan` | A VM that will run the agent |
| `you@example.com` | The first operator's Google account |

The agent hostname must be a name in a domain you control on Cloudflare (not `.lan` or `.local`): Let's Encrypt issues its certificate by proving control of the domain through a DNS record, and that is what lets every VM trust it with no custom certificate authority.

The all-in-one layout:

```
 Operator's browser ──HTTPS──> Cloudflare (Access) ──tunnel──> cloudflared ──> app:3000   fleet.example.com
                                                                                           dashboard only
 VM agents (LAN) ─────HTTPS──> server:443  Traefik (Let's Encrypt) ──────────> app:3000   agent.fleet.example.com
                                                                                           /api/v1 and /health only
```

Rails refuses `/api/v1` on the dashboard hostname and the dashboard on the agent hostname (`cmdb/lib/middleware/host_separation.rb`), so even a misconfigured tunnel cannot expose the agent API.

Steps 1 to 13 are the **all-in-one** layout. For the other one, go to [its section](#existing-postgresql-and-a-tunnel-on-another-machine-deployed-by-github-actions), which reuses steps 3 to 6 and 12 to 13.

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

**Network:** the server needs outbound HTTPS (443) to Cloudflare, Let's Encrypt, Docker Hub, and, to import releases from GitHub, `github.com` and GitHub's release download host (`release-assets.githubusercontent.com`; see [configuration.md](configuration.md#outbound-access)). The tunnel also needs outbound port 7844 (TCP and UDP) to Cloudflare. Inbound, only VMs on the LAN need to reach port 443 of the server. **Do not forward any port from the internet**: the dashboard arrives through the tunnel, which the server dials out to. Traefik also listens on port 8443, for a tunnel connector on another machine; in this layout nothing is routed there (every request gets a 404), and `FLEET_DASHBOARD_BIND_ADDRESS=127.0.0.1` in `.env` keeps it off the LAN.

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
openssl rand -hex 24      # for DATABASE_PASSWORD
sudo editor .env
```

Keep the `COMPOSE_FILE=compose.yaml:compose.bundled.yaml` line: it adds the database and `cloudflared` containers, and every `docker compose` command below reads it from `.env`. Fill in every other uncommented value: the two hostnames, the two generated secrets, the Google client ID and secret, the Cloudflare DNS token and tunnel token, and a real email address for Let's Encrypt (it refuses placeholder domains such as `example.com`). Set `FLEET_RELEASE_KEY_CURRENT` (and `FLEET_RELEASE_KEY_NEXT` if there is one) to the **second line** of `agent/release-keys/current.pub` (and `next.pub`); without a current key no agent release can be imported, so no agent can be installed. Leave everything else commented out unless you have a reason: [configuration.md](configuration.md) explains every setting and its default.

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
| `PGHOST`, `PGUSER`, `PGPASSWORD` | `127.0.0.1`, `cmdb`, the `DATABASE_PASSWORD` from `.env` (add `PGPORT` if you changed `FLEET_DB_PORT`) |

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
- **PostgreSQL major versions** (`postgres:17` in `compose.bundled.yaml`) are never changed by an upgrade. Moving to a new major version is a backup, a new empty database directory, and a restore.
- **cloudflared** is pinned to one version in `compose.bundled.yaml`; it is updated by changing that line in the repository.

## Stop, start, uninstall

```sh
sudo docker compose stop            # stop everything; data stays
sudo docker compose start
sudo docker compose down            # remove the containers and networks; data under /var/lib/fleet-cmdb stays
```

To remove the server completely: uninstall the agents first ([install-agent.md](install-agent.md#uninstall)), take a last backup if you may want the history, then `sudo systemctl disable --now fleet-cmdb-backup.timer`, `sudo docker compose down --rmi local`, and delete `/var/lib/fleet-cmdb`, `/etc/fleet-cmdb`, and `/opt/fleet-cmdb`. In Cloudflare, delete the tunnel, the Access application, and the DNS API token; in Google Cloud, the OAuth client.

## Existing PostgreSQL and a tunnel on another machine, deployed by GitHub Actions

This layout is for a server that already runs PostgreSQL in its own container, from a separate Compose project, and a LAN whose Cloudflare tunnel connector (`cloudflared`) runs on another machine. The stack is `compose.yaml` alone: the app joins the PostgreSQL container's Docker network, and Traefik serves both hostnames, each on its own port. Deploys run from GitHub Actions (`.github/workflows/deploy.yml`) on a self-hosted runner on the LAN, which connects to the server over SSH, ships the commit, writes `.env` from a GitHub environment, and builds and starts the stack on the server. You set secrets and variables in GitHub; you never edit `.env` on the server.

```
 Operator's browser ──HTTPS──> Cloudflare (Access) ──tunnel──> cloudflared on 192.0.2.20
                                                                 │ HTTPS, LAN
                                                                 v
                                     server 192.0.2.10:8443  Traefik ──> app:3000   fleet.example.com, dashboard only
                                     (only from 192.0.2.20)
 VM agents (LAN) ──────HTTPS──>      server 192.0.2.10:443   Traefik ──> app:3000   agent.fleet.example.com, /api/v1 and /health only
                                                                          │
                                                       app ── Docker network ── postgres (your PostgreSQL project)
```

The dashboard is not published on the LAN directly: port 8443 has a Let's Encrypt certificate for the dashboard hostname, by the same DNS challenge as the agent hostname, and answers only the tunnel connector's address (`FLEET_TUNNEL_SOURCE_RANGE`); any other machine gets `403`, so nobody on the LAN can skip Cloudflare Access. Traefik replaces any `X-Forwarded-*` header a client sent on both ports, and removes `Forwarded` and `Client-IP`, so Rails can trust Traefik for both hostnames and still refuse `/api/v1` on the dashboard hostname.

### E1. Check the prerequisites

| You need | Check |
|---|---|
| The server: Linux with Docker Engine and the Compose plugin 2.17 or later, ports 443 and 8443 free | `docker compose version`; `ss -ltn '( sport = :443 or sport = :8443 )'` prints only the header |
| A user on the server for deploys (`deploy` below) in the `docker` group. That group is equivalent to root on the server, which the deploy needs to create the data directories | `ssh deploy@192.0.2.10 docker ps` works without `sudo` |
| PostgreSQL in a container on a Docker network of its own Compose project, reachable on it as `postgres` (or another name: `FLEET_DB_HOST`), with the role `cmdb` owning `cmdb_production`, `cmdb_production_cache`, `cmdb_production_queue`, and `cmdb_production_cable` | `docker network ls` shows the network (for example `postgres_default`); `docker run --rm --network postgres_default postgres:17 pg_isready -h postgres` prints `accepting connections` |
| `cloudflared` running on another machine on the LAN (`192.0.2.20`), with its tunnel managed in the Cloudflare dashboard, and able to reach the server's port 8443 | After the first deploy, `curl -sk -o /dev/null -w '%{http_code}\n' https://192.0.2.10:8443/` from that machine prints `404` (it connects; no hostname was given) |
| A self-hosted GitHub Actions runner on the LAN, registered for this repository, with `bash`, `git`, `ssh`, `ssh-keyscan`, and `gzip`, that can reach the server on port 22 | The runner shows **Idle** in **Settings > Actions > Runners** |
| A domain on Cloudflare (both hostnames are in it), a Google Cloud project, an off-machine backup location, the release public keys | As in step 1 |

**This repository is public**, so be careful with a self-hosted runner: a pull request from a fork runs the workflows of its own branch, and one could ask for `runs-on: self-hosted` and run code on your LAN. In **Settings > Actions > General**, set **Fork pull request workflows from outside collaborators** to **Require approval for all outside collaborators**, and approve only runs you have read. If the repository belongs to an organisation, put the runner in a runner group limited to this repository and to the workflow `.github/workflows/deploy.yml` on `main`. The production secrets themselves are safe from forks: they are in an environment that only `main` can use (E7).

### E2. Prepare the database and the server (once)

The restore drill restores into a scratch database, so the `cmdb` role must be allowed to create databases. Run this once, as the PostgreSQL superuser, in the PostgreSQL container (its name is in `docker ps`):

```sh
docker exec -it <postgres container> psql -U postgres -c 'ALTER ROLE cmdb CREATEDB;'
# ALTER ROLE
```

Without it the drill stops with `the PostgreSQL role cmdb may not create databases … ALTER ROLE cmdb CREATEDB;`. Nothing else in the PostgreSQL project changes: no published port is needed.

On the server, create the deploy directory for the deploy user, and the backup settings directory:

```sh
sudo install -d -o deploy -g deploy -m 0750 /opt/fleet-cmdb
sudo install -d -m 0700 /etc/fleet-cmdb
```

The workflow creates the data directories under `/var/lib/fleet-cmdb` itself (`releases/`, `backup/`, `certs/`), through a container, so the deploy user needs no `sudo`.

### E3. Give the runner SSH access to the server

On your workstation, make a key used only for deploys, and install its public half for the deploy user:

```sh
ssh-keygen -t ed25519 -N '' -C fleet-cmdb-deploy -f fleet-cmdb-deploy
ssh-copy-id -i fleet-cmdb-deploy.pub deploy@192.0.2.10
ssh -i fleet-cmdb-deploy deploy@192.0.2.10 docker version --format '{{.Server.Version}}'   # prints the version
ssh-keyscan -H 192.0.2.10 2>/dev/null       # the server's host keys, for DEPLOY_KNOWN_HOSTS
```

The private key `fleet-cmdb-deploy` goes into the secret `SSH_PRIVATE_KEY` (E7), and then delete both files from the workstation. Compare the host keys `ssh-keyscan` printed with the server's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server) before using them for `DEPLOY_KNOWN_HOSTS`: without that variable each deploy trusts whatever key answers on the LAN at the time.

### E4. Cloudflare DNS token, Google OAuth client, and the agent hostname on the LAN

Do steps [3](#3-create-the-cloudflare-dns-token-for-the-agent-certificate), [5](#5-create-the-google-oauth-client-for-operator-sign-in), and [6](#6-point-the-agent-hostname-at-the-server-on-your-lan) as written. The DNS token is used for both certificates (the agent hostname and the dashboard hostname), so its zone must be the one both are in. The values go into GitHub (E7), not into a file.

### E5. Publish the dashboard through the existing tunnel

In **Cloudflare Zero Trust > Networks > Tunnels**, open the tunnel whose connector runs on `192.0.2.20` and add **one public hostname**:

| Field | Value |
|---|---|
| Subdomain, domain, path | `fleet`, `example.com`, empty |
| Service | Type **HTTPS**, URL **`192.0.2.10:8443`** (the server's LAN address and Traefik's dashboard port) |
| Additional application settings > TLS > **Origin Server Name** | **`fleet.example.com`**, so the connector checks Traefik's certificate against the dashboard hostname |
| **No TLS Verify** | Off |
| HTTP Host Header | Empty (the connector sends `fleet.example.com`) |

The same rules as step 4 apply: **never add the agent hostname to the tunnel**, no path rule for `/api`, and no catch-all that sends other hostnames to the server. Then add the **Access application** for `fleet.example.com` exactly as in [step 4](#4-create-the-tunnel-and-the-access-application-for-the-dashboard) (the tunnel token is not needed in this layout).

Until the first deploy has obtained the dashboard certificate, the public hostname answers `502`. If the connector logs a certificate error, the certificate is not issued yet, or Origin Server Name is missing.

### E6. Optional: a firewall rule

Traefik already refuses every address but `FLEET_TUNNEL_SOURCE_RANGE` on port 8443. A host firewall rule allowing 8443 only from `192.0.2.20` adds a second layer. Note that Docker's published ports bypass `ufw`'s usual rules; use the `DOCKER-USER` chain, or set `FLEET_DASHBOARD_BIND_ADDRESS` and `FLEET_AGENT_BIND_ADDRESS` to the server's LAN address to keep both ports off other interfaces.

### E7. Create the GitHub environment

In **Settings > Environments**, create the environment **`production`**. Under **Deployment branches and tags**, choose **Selected branches and tags** and add `main`, so only `main` can use its secrets; add yourself as a **required reviewer** if every deploy should wait for your approval. Then add these, all in the environment except `DEPLOY_ON_PUSH`:

| Name | Kind | Example | What it is |
|---|---|---|---|
| `SSH_PRIVATE_KEY` | Secret | The whole `fleet-cmdb-deploy` file (E3), `-----BEGIN OPENSSH PRIVATE KEY-----` … | The key the runner logs in to the server with |
| `SECRET_KEY_BASE` | Secret | Output of `openssl rand -hex 64` | Signs and encrypts session cookies. Changing it signs every operator out |
| `DATABASE_PASSWORD` | Secret | The `cmdb` role's password | Password of the existing PostgreSQL role `cmdb` |
| `GOOGLE_CLIENT_ID` | Secret | `123456789012-abc.apps.googleusercontent.com` | Google OAuth client (step 5) |
| `GOOGLE_CLIENT_SECRET` | Secret | `GOCSPX-…` | Google OAuth client secret (step 5) |
| `CLOUDFLARE_DNS_API_TOKEN` | Secret | The token from step 3 | Let's Encrypt DNS challenge for both hostnames |
| `FLEET_ADVISORY_FEED_TOKEN` | Secret, optional | | Only for an advisory mirror that needs a bearer token |
| `DEPLOY_HOST` | Variable | `192.0.2.10` | The server's LAN address or name, as the runner reaches it |
| `DEPLOY_USER` | Variable | `deploy` | The deploy user (E1) |
| `DEPLOY_DIR` | Variable, optional | `/opt/fleet-cmdb` (the default) | Where the code and `.env` live on the server (E2). The backup unit expects `/opt/fleet-cmdb` |
| `DEPLOY_KNOWN_HOSTS` | Variable, recommended | The `ssh-keyscan -H` lines from E3 | The server's SSH host keys. Unset: each deploy trusts the key the server presents |
| `FLEET_DASHBOARD_HOST` | Variable | `fleet.example.com` | Public dashboard hostname |
| `FLEET_AGENT_HOST` | Variable | `agent.fleet.example.com` | Private agent hostname (LAN DNS record, step 6) |
| `ACME_EMAIL` | Variable | `you@example.com` | Let's Encrypt account email: a real address (Let's Encrypt refuses `example.com`) |
| `FLEET_DB_NETWORK` | Variable | `postgres_default` | The PostgreSQL container's Docker network (`docker network ls`). The deploy stops if it does not exist |
| `FLEET_DB_HOST` | Variable, optional | `postgres` (the default) | The PostgreSQL container's name or alias on that network |
| `FLEET_TUNNEL_SOURCE_RANGE` | Variable | `192.0.2.20/32` | The tunnel connector's address; comma-separate several. Keep it to that machine: a range that admits the LAN lets the LAN skip Access |
| `FLEET_RELEASE_KEY_CURRENT` | Variable, needed before installing agents | `RWQ…` (second line of `agent/release-keys/current.pub`) | Release public key (public, so a variable) |
| `FLEET_RELEASE_KEY_NEXT` | Variable, optional | `RWQ…` (second line of `next.pub`) | The next release public key |
| `FLEET_AGENT_BIND_ADDRESS` | Variable, optional | `192.0.2.10` | Address port 443 is published on (default all) |
| `FLEET_DASHBOARD_BIND_ADDRESS` | Variable, optional | `192.0.2.10` | Address port 8443 is published on (default all) |
| `FLEET_DASHBOARD_PORT` | Variable, optional | `8443` (the default) | Port of the dashboard entrypoint on the server; the tunnel's service URL uses it |
| `FLEET_DATA_DIR` | Variable, optional | `/var/lib/fleet-cmdb` (the default) | Release files, backup status, certificates |
| `BACKUP_DIR` | Variable, optional | `/mnt/fleet-cmdb-backups` (the default) | Where backup sets are mounted on the server, for the restore drill |
| `FLEET_EXTRA_SETTINGS` | Variable, optional | `FLEET_SESSION_IDLE_MINUTES=60` (one per line) | Any other non-secret setting of [configuration.md](configuration.md), such as `ACME_CA_SERVER` for a first trial with Let's Encrypt staging |
| `DEPLOY_ON_PUSH` | **Repository** variable (**Settings > Secrets and variables > Actions > Variables**) | `true` | Deploy every push to `main`. Unset or anything else: deploys start only by hand |

A value may not contain a single quote or a line break (the workflow refuses it and names the setting). The workflow checks every required setting before it connects, and prints only names, never values.

### E8. First deploy

**Actions > Deploy > Run workflow**, branch `main`, ref empty. It takes a few minutes the first time (the image builds on the server). The log shows, in order:

1. the commit, and the server's Docker version (SSH works);
2. `wrote .env on the server (mode 0600)` and `shipped <commit>`;
3. on the server (`ops/deploy/deploy.sh`): `database network postgres_default exists`, `configuration is complete`, the build, `releases/ backup/ certs/ ready`, the start, `app: /up answers 200`;
4. `agent hostname: /health answers 503 through Traefik: {…"backup":"failing"…}`. That is expected until the first backup (E10); it does not fail the deploy. Any other answer (no certificate yet after three minutes, a refused connection) fails it, with the place to look;
5. `dashboard entrypoint: refuses this machine (403), as it should`;
6. the containers' status.

**Check** from a VM on the LAN, as in [step 9](#9-check-the-agent-endpoint-and-the-separation) (the agent hostname answers the API's `not_found` with a trusted certificate), and in a browser: `https://fleet.example.com` passes Access and shows the sign-in page. `curl -sk -o /dev/null -w '%{http_code}\n' --resolve fleet.example.com:8443:192.0.2.10 https://fleet.example.com:8443/` from any machine but the tunnel connector prints `403`.

### E9. First operator

```sh
ssh deploy@192.0.2.10
cd /opt/fleet-cmdb
docker compose exec app bin/rails operators:allow EMAIL=you@example.com
# Allowed you@example.com.
```

Then sign in as in [step 10](#10-add-the-first-operator-and-sign-in). Every `docker compose` command in these guides works the same way from `/opt/fleet-cmdb` (as the deploy user, without `sudo`).

### E10. Backups and the restore drill

Follow [backup-and-restore.md, "Schedule it"](backup-and-restore.md#schedule-it), with the existing PostgreSQL settings of `ops/backup/backup.env.example` in `/etc/fleet-cmdb/backup.env`: `FLEET_DB_NETWORK` (the same network as the GitHub variable), `PGHOST=postgres`, `PGUSER=cmdb`, `PGPASSWORD` (the `DATABASE_PASSWORD` secret), and no PostgreSQL client on the server: `backup.sh` runs `pg_dump` in a throwaway `postgres:17` container on that network. Run the first backup, then the drill:

```sh
sudo systemctl start fleet-cmdb-backup.service && journalctl -u fleet-cmdb-backup.service -n 5
cd /opt/fleet-cmdb && docker compose run --rm restore-drill      # … then: Restore drill passed.
```

`/health` turns `ok` within a few minutes of the first backup. Then set up monitoring and import a release: [steps 12 and 13](#12-check-health-and-set-up-monitoring).

### E11. Upgrade, change a setting, roll back

- **Upgrade:** merge to `main`. With `DEPLOY_ON_PUSH=true` the push deploys; otherwise run the workflow. `db:prepare` runs the new migrations on start. Take a backup first when the change has migrations (`sudo systemctl start fleet-cmdb-backup.service`).
- **Change a setting:** change the GitHub secret or variable, then run the workflow. `.env` on the server is rewritten by every deploy; an edit there is lost.
- **Roll back:** run the workflow with **ref** set to the earlier commit of `main` (`git log --oneline origin/main`), or open that commit's earlier successful Deploy run and choose **Re-run all jobs**. Only commits of `main` are deployed. If the newer version ran migrations, the old code may not run on the migrated database: restore the backup taken before the upgrade ([backup-and-restore.md](backup-and-restore.md#restore)), then deploy the old commit.
- Two deploys never overlap: a second one waits for the first.

Logs, certificate renewal, and uninstalling are as in the all-in-one sections above, run as the deploy user from `/opt/fleet-cmdb` (there is no `db` or `cloudflared` service; their logs are in your PostgreSQL project and on the tunnel machine). Data lives in `/var/lib/fleet-cmdb` (no `postgres/` directory: the database is yours) and the certificates for both hostnames are in `certs/acme.json`.
