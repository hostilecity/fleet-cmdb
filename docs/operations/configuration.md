# Configuration reference

Every setting of the server, with its default. With the Compose deployment ([install-server.md](install-server.md)) they are set in `/opt/fleet-cmdb/.env`, which `compose.yaml` reads; a setting that is not in `.env` is not passed to the app, so the default applies. **Leave optional settings commented out rather than empty**: an empty value is passed as empty, and a number setting then stops the boot. After changing `.env`, apply it with `sudo docker compose up -d` (it recreates the containers whose settings changed) and check `sudo docker compose ps`.

**Deployed by GitHub Actions** (the existing PostgreSQL layout, [install-server.md](install-server.md#existing-postgresql-and-a-tunnel-on-another-machine-deployed-by-github-actions)): `.github/workflows/deploy.yml` writes `.env` on every deploy from the `production` environment's secrets and variables of the same names (the table in [E7](install-server.md#e7-create-the-github-environment)); any other non-secret setting below goes into the variable `FLEET_EXTRA_SETTINGS`, one `NAME=value` per line. Change it there and deploy again: an edit of `.env` on the server is lost at the next deploy.

Settings marked *fixed* are set by `compose.yaml` itself and are listed so the reference is complete; change them only when running the app some other way.

## Hostnames

| Setting | Default | |
|---|---|---|
| `FLEET_DASHBOARD_HOST` | required | Public dashboard hostname, published only through the Cloudflare tunnel. The app serves the dashboard, sign-in, and the OAuth callback only on this name |
| `FLEET_AGENT_HOST` | required | Private agent API hostname, resolving only on the LAN. The app serves `/api/v1`, `/up`, and `/health` only on this name. Must differ from the dashboard hostname; the boot stops otherwise |
| `FLEET_DASHBOARD_URL` | `https://$FLEET_DASHBOARD_HOST` | Base of the approval link the agent installer prints, if the dashboard is on another scheme or port |
| `FLEET_TRUSTED_PROXIES` | *fixed*: `$FLEET_PROXY_SUBNET` | Addresses or CIDRs (comma-separated) allowed to set `X-Forwarded-Host`, `X-Forwarded-For`, `Client-IP`, and `Forwarded`; loopback is always trusted. Compose trusts only the network Traefik shares with the app, so agent rate limits see each VM's address. Traefik trusts no client's forwarded headers on either of its ports (it replaces `X-Forwarded-*` and removes `Forwarded` and `Client-IP`), so both hostnames can come through it. The bundled tunnel connector (all-in-one layout) reaches the app directly and is deliberately not trusted: it passes on headers a browser sent, so trusting it would let a client claim the agent hostname with `X-Forwarded-Host` |

## Secrets

Keep a copy of each with your other secrets, never in git or in the backup set ([backup-and-restore.md](backup-and-restore.md#what-is-backed-up)).

| Setting | Default | |
|---|---|---|
| `SECRET_KEY_BASE` | required | Signs and encrypts the session cookie. `openssl rand -hex 64`. Changing it signs every operator out |
| `RAILS_MASTER_KEY` | not used | The repository's `cmdb/config/credentials.yml.enc` belongs to its owner and holds nothing a deployment needs; `SECRET_KEY_BASE` replaces it. Not passed by `compose.yaml` |
| `DATABASE_PASSWORD` | required | Password of the PostgreSQL role `cmdb`. With an existing PostgreSQL, the password that role already has. In the all-in-one layout the bundled database container sets it **only when the database is first created**; changing it later in `.env` alone breaks the connection (change it in PostgreSQL too: `ALTER ROLE cmdb PASSWORD '…'`) |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | required | Google OAuth web client for operator sign-in. Redirect URI `https://$FLEET_DASHBOARD_HOST/auth/google_oauth2/callback` |
| `CLOUDFLARE_DNS_API_TOKEN` | required | Given to Traefik only (as `CF_DNS_API_TOKEN`), for the Let's Encrypt DNS challenge: the agent hostname's certificate and, with `FLEET_TUNNEL_SOURCE_RANGE` set, the dashboard hostname's. Permissions Zone:Read and DNS:Edit, for the one zone of the hostnames |
| `CLOUDFLARE_TUNNEL_TOKEN` | required in the all-in-one layout; not used otherwise | Given to the bundled `cloudflared` only (as `TUNNEL_TOKEN`). The tunnel's single public hostname is the dashboard |
| `ACME_EMAIL` | required | Let's Encrypt account email, for expiry notices. Use a real address: Let's Encrypt refuses `example.com` and other reserved domains, and no certificate is issued |
| `ACME_CA_SERVER` | Let's Encrypt production | Set to `https://acme-staging-v02.api.letsencrypt.org/directory` for a trial run (agents will not trust the result). Delete `certs/acme.json` when switching back |

## Agent releases

| Setting | Default | |
|---|---|---|
| `FLEET_RELEASE_KEY_CURRENT`, `FLEET_RELEASE_KEY_NEXT` | none | The release public keys: the second (base64) line of `agent/release-keys/current.pub` and `next.pub`, or both lines. A malformed key, or a next key without a current one, stops the boot. With no current key every import is refused, so no agent can be installed. The server never holds a private key. After a key rotation, update these with `current.pub` ([docs/releases.md](../releases.md#rotation)) |
| `FLEET_RELEASE_REPOSITORY` | `hostilecity/fleet-cmdb` | GitHub repository releases are imported from (tag `agent-v<version>`) |
| `FLEET_RELEASES_DIR` | *fixed*: `/rails/storage/releases`, which is `$FLEET_DATA_DIR/releases` on the host | Release binaries. Backed up by `ops/backup/backup.sh` |
| `FLEET_RELEASE_DOWNLOAD_RATE_LIMIT_PER_MINUTE` | `60` | Release downloads per client address |
| `FLEET_ROLLOUT_SPREAD_SECONDS` | `300` | Window over which opening a rollout stage spreads the update directive, so VMs behind one address do not hit the download limit together |
| `FLEET_UPDATE_CONFIRMATION_TIMEOUT_MINUTES` | `30` | A host sent the update directive that has not reported by then is `unconfirmed`, which halts the rollout |
| `FLEET_MINIMUM_AGENT_VERSION` | `0.1.0` | Older agents get `426 agent_version_unsupported` on reports, but can still heartbeat, download releases, and update |

### Outbound access

Importing a release **from GitHub** needs outbound HTTPS from the server to `github.com` (`https://github.com/$FLEET_RELEASE_REPOSITORY/releases/download/agent-v<version>/…`) and to the host GitHub redirects release downloads to, currently `release-assets.githubusercontent.com` (formerly `objects.githubusercontent.com`). The GitHub API (`api.github.com`) is not used, and no token is needed. **Uploading** a release from the Agents page needs no outbound access at all. **Advisory data** needs outbound HTTPS to `storage.googleapis.com` (the default `FLEET_ADVISORY_FEED_URL`), or to your mirror; with the setting empty the server needs none, and archives are imported with `bin/rails advisories:import`. Besides that, the stack reaches Cloudflare (tunnel and DNS API), Let's Encrypt, and Docker Hub (when pulling images).

## Advisory data

The server downloads vulnerability advisories itself and matches them against the packages agents report; agents never fetch advisories. How the refresh, imports, and the withdrawal guard work: [cmdb/README.md](../../cmdb/README.md#advisory-data) and [health-and-jobs.md](health-and-jobs.md).

| Setting | Default | |
|---|---|---|
| `FLEET_ADVISORY_FEED_URL` | `https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip` | The OSV archive the refresh downloads (Debian's covers every release; only `Debian:13` is kept). HTTPS only, or empty to turn the refresh off |
| `FLEET_ADVISORY_FEED_TOKEN` | none | Sent as a bearer token, for a mirror that needs one; also read from credentials (`advisories.feed_token`). Never logged or shown |
| `FLEET_ADVISORY_MAX_DOWNLOAD_MB` | `512` | The largest archive downloaded or imported |
| `FLEET_ADVISORY_MAX_AGE_HOURS` | `48` | Older data shows a warning on the dashboard |
| `FLEET_ADVISORY_WITHDRAW_SHARE` | `0.10` | A full import that would mark more than this share of an ecosystem's current advisories withdrawn is refused with the counts until an operator allows them. A decimal from 0 to 1; anything else stops the server at boot |
| `FLEET_ADVISORY_WITHDRAW_MIN_RECORDS` | `1000` | A full import with fewer records than this for an ecosystem is refused if it would withdraw any of its advisories, until an operator allows them. A whole number, 0 or more |
| `FLEET_ADVISORY_REFRESH_COOLDOWN` | `300` | Seconds after a refresh starts before the dashboard's "Refresh now" may start another. A whole number, at least 1: any other value stops the server at boot with an error naming the setting |

The real OSV Debian archive measured 77.4 MiB zipped, 73,658 records, and 260.9 MiB of JSON (largest record 34.1 KiB) on 2026-11-07, well inside these limits; check again when another distribution's feed is added.

## Agent API and enrollment

| Setting | Default | |
|---|---|---|
| `FLEET_API_RATE_LIMIT_PER_MINUTE` | `120` | Per credential, across authenticated endpoints; also per address for onboarding polls |
| `FLEET_ENROLL_RATE_LIMIT_PER_MINUTE` | `10` | Per client address, on `POST /api/v1/enroll` |
| `FLEET_ENROLLMENT_TOKEN_TTL_HOURS` | `24` | Lifetime of a pre-registration one-time token |
| `FLEET_ONBOARDING_TTL_MINUTES` | `10` | How long an onboarding request waits for approval |
| `FLEET_ONBOARDING_POLL_SECONDS` | `5` | Minimum time between the installer's polls |
| `FLEET_ONBOARDING_MAX_OPEN` | `50` | Onboarding requests awaiting approval, in total |
| `FLEET_ONBOARDING_MAX_OPEN_PER_ADDRESS` | `5` | Onboarding requests awaiting approval, per client address |
| `FLEET_ONBOARDING_RATE_LIMIT_PER_MINUTE` | `10` | Onboarding starts per client address |
| `FLEET_API_SCHEMAS_DIR` | *fixed* by the image: `/rails/api-schemas` (`../docs/api/schemas` outside it) | The agent API JSON Schemas, read at runtime; the boot stops without them |

## Operator sessions

| Setting | Default | |
|---|---|---|
| `FLEET_SESSION_IDLE_MINUTES` | `120` | Sign out after this long without a request |
| `FLEET_SESSION_ABSOLUTE_HOURS` | `12` | Sign out this long after signing in, however active |

The operator allowlist is not a setting: `bin/rails operators:allow EMAIL=…` ([install-server.md](install-server.md#10-add-the-first-operator-and-sign-in)).

## Backups and health

| Setting | Default | |
|---|---|---|
| `FLEET_BACKUP_MAX_AGE_HOURS` | `26` | `/health` fails its `backup` check when the last complete backup is older than this, or has never run |
| `FLEET_BACKUP_STATUS_FILE` | *fixed*: `/rails/storage/backup/last_success`, which is `$FLEET_DATA_DIR/backup/last_success` on the host | Touched by `backup.sh` after each complete backup; the app reads its time |
| `BACKUP_DIR` | `/mnt/fleet-cmdb-backups` | Where backup sets are mounted, for `docker compose run --rm restore-drill`. Set it to the `BACKUP_DIR` of `/etc/fleet-cmdb/backup.env` |
| `FLEET_RESTORE_DRILL` | unset; *fixed* to `1` by `restore-drill.sh` | Makes the drill's boot use an in-memory cache, so it never writes to the live cache database |

Backup **retention** is set in `/etc/fleet-cmdb/backup.env`, not here: `BACKUP_RETENTION_DAYS` (default 14) and `BACKUP_KEEP_MIN` (default 3); so is, with an existing PostgreSQL container, `FLEET_DB_NETWORK` with `BACKUP_IMAGE` (default `postgres:17`), which makes `backup.sh` run `pg_dump` in a container on that network; all of the backup script's settings are in [backup-and-restore.md](backup-and-restore.md#schedule-it) and `ops/backup/backup.sh`. **Data retention** (snapshots, report ids, status history; default 90 days) is a setting in the database, changed with `bin/rails settings:retention DAYS=…` ([health-and-jobs.md](health-and-jobs.md#retention)); so are the liveness thresholds ([fleet-operations.md](fleet-operations.md#change-the-liveness-thresholds)).

## Paths, ports, and networks on the host

Read by `compose.yaml` and `compose.bundled.yaml` only.

| Setting | Default | |
|---|---|---|
| `COMPOSE_FILE` | `compose.yaml:compose.bundled.yaml` in `.env.example`; `compose.yaml` when written by the deploy workflow | Read by Docker Compose itself. With `compose.bundled.yaml` the stack includes its own PostgreSQL and `cloudflared` (all-in-one); without it the app uses an existing PostgreSQL on `FLEET_DB_NETWORK` |
| `FLEET_DB_NETWORK` | `fleet-cmdb-database` | Docker network of the PostgreSQL server; the app and the restore drill join it. Without `compose.bundled.yaml` it must already exist (created by your PostgreSQL Compose project, for example `postgres_default`), and `ops/deploy/deploy.sh` stops if it does not; with it, the stack creates it |
| `FLEET_DB_HOST` | `postgres` | PostgreSQL's name on that network, passed to the app as `PGHOST`. The bundled database answers to `postgres` |
| `FLEET_TUNNEL_SOURCE_RANGE` | not set | Addresses or CIDRs (comma-separated, not `/0`) of the machine running the Cloudflare tunnel connector, when it is not this one. Traefik then routes the dashboard hostname on its dashboard port, with a Let's Encrypt certificate, to those addresses only (others get `403`). Not set: nothing is routed on that port |
| `FLEET_DASHBOARD_BIND_ADDRESS` | `0.0.0.0` | Address Traefik's dashboard port is published on. In the all-in-one layout set `127.0.0.1` to keep it off the LAN |
| `FLEET_DASHBOARD_PORT` | `8443` | Port of the dashboard entrypoint on this machine; the tunnel's service URL is `https://<server address>:<port>` |
| `FLEET_DATA_DIR` | `/var/lib/fleet-cmdb` | Holds `releases/`, `backup/`, `certs/`, and in the all-in-one layout `postgres/` |
| `FLEET_AGENT_BIND_ADDRESS` | `0.0.0.0` | Address Traefik's port 443 is published on. Set it to the server's LAN address to keep it off other interfaces |
| `FLEET_DB_PORT` | `5432` | All-in-one layout: the bundled PostgreSQL's port on `127.0.0.1`, for `backup.sh` (then set `PGPORT` in `backup.env` too) |
| `FLEET_PROXY_SUBNET` | `172.30.47.0/28` | Docker network shared by Traefik and the app, and the only one Rails trusts for forwarded headers. Change it only if the range is in use on the machine |

## App process

| Setting | Default | |
|---|---|---|
| `RAILS_LOG_LEVEL` | `info` | `debug` logs much more, including values that may be personal; use it briefly |
| `RAILS_MAX_THREADS` | Puma: `3` threads; database pool: `5` | Sets both. Keep the default unless the dashboard is slow under load |
| `JOB_CONCURRENCY` | `1` | Solid Queue worker processes |
| `RAILS_ENV` | *fixed*: `production` | |
| `PORT` | *fixed*: `3000` | Puma's port inside the container; nothing publishes it on the host |
| `SOLID_QUEUE_IN_PUMA` | *fixed*: `1` | Background jobs and the recurring schedule run inside the app container |
| `PGHOST` | *fixed*: `$FLEET_DB_HOST` | The PostgreSQL server, for all four databases |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`; `PGUSER`, `PGPASSWORD` | *fixed*: `cmdb` and `$DATABASE_PASSWORD` | Given to the bundled database container (role created on first start) and to the restore drill (libpq) |
| `DATABASE_URL`, `CACHE_DATABASE_URL`, `QUEUE_DATABASE_URL`, `CABLE_DATABASE_URL` | not set | Override a database's connection (the restore drill sets `DATABASE_URL` to its scratch database). Not used by the Compose deployment |

Not settings: `SECRET_KEY_BASE_DUMMY` is used only while building the image, and `BUNDLE_GEMFILE`, `FLEET_API_SCHEMAS_DIR`, and `FLEET_RULES_SCHEMA_DIR` are set by the image; `WEB_CONCURRENCY` and `PIDFILE` (Puma) are not passed by `compose.yaml`; `CI`, `GITHUB_ACTIONS`, `COVERAGE_MINIMUM`, `NO_COVERAGE`, and `SHOW_TIMINGS` affect only the test suite and CI; `BACKUP_IN_CONTAINER` is set by `backup.sh` for its own container; the `DEPLOY_*` variables, `SSH_PRIVATE_KEY`, and `FLEET_EXTRA_SETTINGS` belong to the deploy workflow, not the server; and `EMAIL`, `DISPLAY_NAME`, `VM_HOSTNAME`, `TAGS`, `DESCRIPTION`, `HOST_ID`, `ONLINE_MINUTES`, `STALE_MINUTES`, `DAYS`, `COUNTS`, `FULL`, `ALLOW_WITHDRAWALS`, and `DISABLE_MISSING` are arguments of the `bin/rails` tasks named in these guides.
