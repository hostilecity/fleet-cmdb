# Configuration reference

Every setting of the server, with its default. The deploy workflow (`.github/workflows/cd.yml`, [install-server.md](install-server.md)) passes them to the `fleet-cmdb` container from the GitHub environment `production`: the settings in the [install guide's table](install-server.md#2-create-the-github-environment) have a secret or variable of the same name, and any other non-secret setting below goes into the variable `FLEET_EXTRA_SETTINGS`, one `NAME=value` per line. A setting that is not set is not passed, so the default applies (an empty value is passed as empty, and a number setting then stops the boot). Change a setting in GitHub and run the workflow again.

Settings marked *fixed* are set by the workflow or the image and are listed so the reference is complete.

## Hostnames

| Setting | Default | |
|---|---|---|
| `FLEET_DASHBOARD_HOST` | required | Public dashboard hostname, published through the Cloudflare tunnel. The app serves the dashboard, sign-in, and the OAuth callback only on this name |
| `FLEET_AGENT_HOST` | required | The server VM's internal hostname, resolving only on your network: agents and the tunnel connect to it over HTTPS (ADR 0024). The app serves `/api/v1`, `/up`, and `/health` only on this name. Must differ from the dashboard hostname, and the server's certificate must cover it; the boot stops otherwise |
| `FLEET_DASHBOARD_URL` | `https://$FLEET_DASHBOARD_HOST` | Base of the approval link the agent installer prints, if the dashboard is on another scheme or port |
| `FLEET_TRUSTED_PROXIES` | none (loopback only) | Addresses or CIDRs (comma-separated) allowed to set `X-Forwarded-Host`, `X-Forwarded-For`, `Client-IP`, and `Forwarded`; loopback is always trusted. **Leave it unset in this deployment**: the tunnel connector reaches the app directly and passes on headers a browser sent, so trusting it would let a client claim the agent hostname with `X-Forwarded-Host`. For a TLS proxy in front of the app, if a deployment adds one |

## Secrets

Keep a copy of each with your other secrets (GitHub never shows a secret again), never in git.

| Setting | Default | |
|---|---|---|
| `SECRET_KEY_BASE` | required | Signs and encrypts the session cookie. `openssl rand -hex 64`. Changing it signs every operator out |
| `RAILS_MASTER_KEY` | not used | The repository's `cmdb/config/credentials.yml.enc` belongs to its owner and holds nothing a deployment needs; `SECRET_KEY_BASE` replaces it. Not passed by the workflow |
| `DATABASE_PASSWORD` | required | Password of the existing PostgreSQL role `cmdb`. To change it, change it in PostgreSQL (`ALTER ROLE cmdb PASSWORD '…'`) and in GitHub, then deploy |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | required | Google OAuth web client for operator sign-in. Redirect URI `https://$FLEET_DASHBOARD_HOST/auth/google_oauth2/callback` |
| `FLEET_TLS_CERT_BASE64`, `FLEET_TLS_KEY_BASE64` | none (no HTTPS) | The server's certificate and its private key (ADR 0024): each PEM file base64-encoded onto one line. The deploy workflow encodes them from the secrets `FLEET_TLS_CERT` and `FLEET_TLS_KEY`. Puma then serves HTTPS on `FLEET_TLS_PORT`, TLS 1.2 and later. Set both or neither; a key that does not match, or a certificate that does not cover `FLEET_AGENT_HOST`, stops the server at boot. The Settings page shows the certificate's expiry |

## Agent releases

| Setting | Default | |
|---|---|---|
| `FLEET_RELEASE_KEY_CURRENT`, `FLEET_RELEASE_KEY_NEXT` | none | The release public keys: the second (base64) line of `agent/release-keys/current.pub` and `next.pub`, or both lines. A malformed key, or a next key without a current one, stops the boot. With no current key every import is refused, so no agent can be installed. The server never holds a private key. After a key rotation, update these with `current.pub` ([docs/releases.md](../releases.md#rotation)) |
| `FLEET_RELEASE_REPOSITORY` | `hostilecity/fleet-cmdb` | GitHub repository releases are imported from (tag `agent-v<version>`) |
| `FLEET_RELEASES_DIR` | `/rails/storage/releases`, in the Docker volume `fleet-cmdb_storage` | Release binaries. Uploaded releases exist only here |
| `FLEET_RELEASE_DOWNLOAD_RATE_LIMIT_PER_MINUTE` | `60` | Release downloads per client address |
| `FLEET_ROLLOUT_SPREAD_SECONDS` | `300` | Window over which opening a rollout stage spreads the update directive, so VMs behind one address do not hit the download limit together |
| `FLEET_UPDATE_CONFIRMATION_TIMEOUT_MINUTES` | `30` | A host sent the update directive that has not reported by then is `unconfirmed`, which halts the rollout |
| `FLEET_MINIMUM_AGENT_VERSION` | `0.1.0` | Older agents get `426 agent_version_unsupported` on reports, but can still heartbeat, download releases, and update |

### Outbound access

Importing a release **from GitHub** needs outbound HTTPS from the server to `github.com` (`https://github.com/$FLEET_RELEASE_REPOSITORY/releases/download/agent-v<version>/…`) and to the host GitHub redirects release downloads to, currently `release-assets.githubusercontent.com` (formerly `objects.githubusercontent.com`). The GitHub API (`api.github.com`) is not used, and no token is needed. **Uploading** a release from the Agents page needs no outbound access at all. **Advisory data** needs outbound HTTPS to `storage.googleapis.com` (the default `FLEET_ADVISORY_FEED_URL`), or to your mirror; with the setting empty the server needs none, and archives are imported with `bin/rails advisories:import`. Besides that, building the image on the server needs Docker Hub and the Ruby gem sources.

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
| `FLEET_DEBIAN_TRACKER_URL` | `https://security-tracker.debian.org/tracker/data/json` | Debian's triage beside each finding (ADR 0022): the one JSON document the scheduled refresh downloads, 15 minutes after the OSV refresh. HTTPS only, or empty to turn the refresh off (import the file with `bin/rails advisories:triage_import FILE=...` instead). Its staleness warning uses `FLEET_ADVISORY_MAX_AGE_HOURS`, and its truncation guard `FLEET_ADVISORY_WITHDRAW_SHARE` per release |
| `FLEET_DEBIAN_TRACKER_MAX_DOWNLOAD_MB` | `512` | The largest tracker document downloaded or imported. A whole number, at least 1 |

The real OSV Debian archive measured 77.4 MiB zipped, 73,658 records, and 260.9 MiB of JSON (largest record 34.1 KiB) on 2026-11-07, well inside these limits; check again when another distribution's feed is added. The Debian Security Tracker's document measured 84.2 MiB (4,180 source packages, 79,646 entries) the same day.

The refreshes need outbound HTTPS from the server to `storage.googleapis.com` (OSV) and `security-tracker.debian.org` (Debian triage). Without it, set both URLs empty and import the files by hand (`cmdb/README.md`).

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
| `FLEET_AGENT_TRUST_DIR` | *fixed* by the image: `/rails/agent-trust` (`../agent/trust` outside it) | The certificate authorities compiled into the agent (ADR 0024). The install page gives curl the one that signed the server's certificate |

## Operator sessions

| Setting | Default | |
|---|---|---|
| `FLEET_SESSION_IDLE_MINUTES` | `120` | Sign out after this long without a request |
| `FLEET_SESSION_ABSOLUTE_HOURS` | `12` | Sign out this long after signing in, however active |

The operator allowlist is not a setting: `bin/rails operators:allow EMAIL=…` ([install-server.md](install-server.md#5-add-the-first-operator)).

## Backups and health

Backups are not part of this deployment yet; they get their own issue. Until a backup has run, `/health` reports `503` with `"backup":"failing"`.

| Setting | Default | |
|---|---|---|
| `FLEET_BACKUP_MAX_AGE_HOURS` | `26` | `/health` fails its `backup` check when the last complete backup is older than this, or has never run |
| `FLEET_BACKUP_STATUS_FILE` | `/rails/storage/backup/last_success`, in the Docker volume | Touched by `ops/backup/backup.sh` after each complete backup; the app reads its time |
| `FLEET_RESTORE_DRILL` | unset; *fixed* to `1` by `restore-drill.sh` | Makes the drill's boot use an in-memory cache, so it never writes to the live cache database |

**Data retention** (snapshots, report ids, status history; default 90 days) is a setting in the database, changed with `bin/rails settings:retention DAYS=…` ([health-and-jobs.md](health-and-jobs.md#retention)); so are the liveness thresholds ([fleet-operations.md](fleet-operations.md#change-the-liveness-thresholds)).

## Database

| Setting | Default | |
|---|---|---|
| `FLEET_DB_NETWORK` | required (workflow variable) | Docker network of the existing PostgreSQL container; the app container joins it. The deploy stops if it does not exist |
| `FLEET_DB_HOST` | `postgres` (workflow variable) | The PostgreSQL container's name on that network, passed to the app as `PGHOST` |

## App process

| Setting | Default | |
|---|---|---|
| `RAILS_LOG_LEVEL` | `info` | `debug` logs much more, including values that may be personal; use it briefly |
| `RAILS_MAX_THREADS` | Puma: `3` threads; database pool: `5` | Sets both. Keep the default unless the dashboard is slow under load |
| `JOB_CONCURRENCY` | `1` | Solid Queue worker processes |
| `RAILS_ENV` | *fixed* by the image: `production` | |
| `PORT` | *fixed* by the image: `3000` | Puma's plain-HTTP port inside the container, for its health checks; not published |
| `FLEET_TLS_PORT` | `3443` | Puma's HTTPS port inside the container, published as port 443 on the server |
| `SOLID_QUEUE_IN_PUMA` | *fixed* by the workflow: `1` | Background jobs and the recurring schedule run inside the app container |
| `PGHOST` | *fixed* by the workflow: `$FLEET_DB_HOST` | The PostgreSQL server, for all four databases (role `cmdb`, set in `config/database.yml`) |
| `DATABASE_URL`, `CACHE_DATABASE_URL`, `QUEUE_DATABASE_URL`, `CABLE_DATABASE_URL` | not set | Override a database's connection (the restore drill sets `DATABASE_URL` to its scratch database). Not used by the deployment |

Not settings: `SECRET_KEY_BASE_DUMMY` is used only while building the image, and `BUNDLE_GEMFILE`, `FLEET_API_SCHEMAS_DIR`, `FLEET_RULES_SCHEMA_DIR`, and `FLEET_AGENT_TRUST_DIR` (the agent's compiled-in certificate authorities, `agent/trust`) are set by the image; `WEB_CONCURRENCY` and `PIDFILE` (Puma) are not needed; `CI`, `GITHUB_ACTIONS`, `COVERAGE_MINIMUM`, `NO_COVERAGE`, and `SHOW_TIMINGS` affect only the test suite and CI; the `DEPLOY_*` variables, `SSH_PRIVATE_KEY`, and `FLEET_EXTRA_SETTINGS` belong to the deploy workflow; `BACKUP_*` and the libpq variables `PGUSER`, `PGPASSWORD`, `PGPORT` are read by the scripts in `ops/backup/`; and `EMAIL`, `DISPLAY_NAME`, `VM_HOSTNAME`, `TAGS`, `DESCRIPTION`, `HOST_ID`, `ONLINE_MINUTES`, `STALE_MINUTES`, `DAYS`, `COUNTS`, `FULL`, `ALLOW_WITHDRAWALS`, and `DISABLE_MISSING` are arguments of the `bin/rails` tasks named in these guides.
