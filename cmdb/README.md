# cmdb: Fleet CMDB server and dashboard

The Rails application: host records, dashboard, agent API, evaluation, and audit log. Requirements are in `../docs/requirements.md`; the stack was decided in `../docs/decisions/0002-server-stack.md`.

| | |
|---|---|
| Ruby | 3.4.10 (`.ruby-version`) |
| Rails | 8.1 |
| Database | PostgreSQL (primary, plus separate cache, queue, and cable databases) |
| Background jobs, cache, cable | Solid Queue, Solid Cache, Solid Cable |
| Front end | Hotwire (Turbo and Stimulus), importmap, Propshaft |
| Tests | RSpec, FactoryBot, WebMock, SimpleCov |
| Checks | rubocop-rails-omakase, brakeman, bundler-audit |

## Development environment (macOS)

**Do not use the macOS system Ruby.** `/usr/bin/ruby` is 2.6.10 and cannot run Rails 8. Use Ruby 3.4.x through [chruby](https://github.com/postmodern/chruby) and [ruby-install](https://github.com/postmodern/ruby-install):

```sh
ruby-install ruby 3.4.10        # once
chruby ruby-3.4.10              # per shell; or add auto-switching so .ruby-version is honoured
ruby -v                         # must print 3.4.10
```

PostgreSQL comes from Homebrew and must be running:

```sh
brew install postgresql@18
brew services start postgresql@18
pg_isready                      # should say "accepting connections"
```

The development and test databases use your macOS user over the local socket, so no password is needed.

## First run

From this directory:

```sh
bin/setup --skip-server   # installs gems and creates and prepares all databases
bin/ci                    # runs the full check (see below)
bin/dev                   # starts the app on http://localhost:3000 with Solid Queue inside Puma
```

`bin/setup` is idempotent; add `--reset` to drop and recreate the development databases.

## Tests and checks

```sh
bundle exec rspec                       # the test suite (coverage report in coverage/)
NO_COVERAGE=1 bundle exec rspec spec/requests   # a subset, without coverage
bin/rubocop                             # style
bin/brakeman                            # static security analysis
bin/bundler-audit                       # known-vulnerable gems
bin/ci                                  # all of the above, in order (this is what CI runs)
```

Tests never reach the network (WebMock blocks everything except localhost). Put factories in `spec/factories/` and shared helpers in `spec/support/`.

## Databases

Development uses `cmdb_development` plus `cmdb_development_cache`, `_queue`, and `_cable`, mirroring production's layout. Tests use a single `cmdb_test` database with the test adapters for jobs, cache, and cable.

Recurring jobs are declared in `config/recurring.yml` and run by Solid Queue's scheduler. Later issues add their jobs there.

### Hosts and the audit log

- **Hosts** (`app/models/host.rb`) change enrollment state only through `activate!`, `revoke!`, `begin_reenrollment!`, and `retire!`, which follow the FR-1.1 table. Any other change raises `Host::InvalidTransition`. Create hosts with `Host.register!` and change them with `#edit!`. Hosts are retired, never deleted.
- **Audit entries** are written only with `Audit.record` (`app/models/audit.rb`), inside the same transaction as the change. Action names live in `Audit::Actions`.
  - Before and after values whose keys look like secrets (token, credential, digest, and so on) raise outside production and are replaced with `[FILTERED]` in production.
- **The audit log is append-only in the database too.** A trigger rejects `UPDATE`, `DELETE`, and `TRUNCATE` on `audit_entries`, so tasks that truncate every table, such as `bin/rails db:truncate_all` and `db:seed:replant`, fail by design. Use `db:reset` for a fresh development database.
  - The trigger and its function live in `db/functions/` and `db/triggers/`. The [fx](https://github.com/teoljungberg/fx) gem records them in `db/schema.rb`, so `db:prepare` and `db:schema:load` recreate them.

### Heartbeats and liveness

- **Heartbeats.** `POST /api/v1/heartbeat` sets `last_seen_at` from the server clock. The agent's own clock goes in `agent_reported_at` and is never used for liveness. A host that wasn't online becomes online at once, with a row in `host_status_events`, the status history (not the audit log).
- **Liveness evaluation.** `LivenessEvaluationJob` runs every minute (`config/recurring.yml`). It moves active hosts to `online`, `stale` or `offline` by age, writing a history row only on a change. Rows a heartbeat is holding are skipped (`FOR UPDATE SKIP LOCKED`) and picked up on the next run.
- **What each host shows:**
  - a host that has never sent a heartbeat has no liveness status and shows "awaiting first contact";
  - hosts that are not active show their enrollment state instead.
- **Thresholds** default to 3 and 15 minutes. Change them on the dashboard's Settings page, or from the command line; each change is audited:

```sh
bin/rails settings:show
bin/rails settings:liveness ONLINE_MINUTES=3 STALE_MINUTES=15
```

### Inventory reports

`POST /api/v1/reports/inventory` (FR-1.3, DEC-07):

- **Validation and checks.** The body is validated against `docs/api`, then normalised and checked by `lib/agent_api/inventory_report.rb`:
  - control characters are stripped (markup is kept and escaped when rendered);
  - addresses must be valid CIDRs;
  - free space cannot exceed size, and available memory cannot exceed total;
  - mounts and interfaces cannot repeat.

  A report that fails writes nothing.
- **Storage.** `InventoryRecorder` stores a valid report under the host row lock:
  - `inventory_report_receipts`: report ids already processed. A retried report is answered `duplicate: true` and changes nothing.
  - `host_inventories`: the current stable and volatile fields and warnings, replaced on every report.
  - `inventory_snapshots`: the stable fields, written only when their hash changes. A boot id change counts, so reboots appear.
- **Clone detection (FR-S.1).** A machine id different from the one the credential was enrolled with sets `hosts.machine_id_mismatch_at`. It is audited once and cleared when the host is re-enrolled.
- **Audit entries.** Ordinary reports write none; only the first inventory and a machine id mismatch are audited.

## Hostnames and operator sign-in

The server has two faces (DEC-05), each on its own hostname:

| Hostname (setting) | Serves | Reached through |
|---|---|---|
| Dashboard (`FLEET_DASHBOARD_HOST`) | Dashboard, sign-in, Google OAuth callback | The Cloudflare tunnel, behind Cloudflare Access |
| Agent API (`FLEET_AGENT_HOST`) | `/api/v1/*`, and the `/up` health check (later also `/health`) | The LAN only, through the agent TLS proxy |
| `localhost` | `/up` only | The container health check |

- **Host guard.** `lib/middleware/host_separation.rb` runs first in the middleware stack. It returns an empty 404 for a path on the wrong hostname or for an unknown host. Each route is also constrained to its hostname in `config/routes.rb`, as a second line of defence.
- **`X-Forwarded-Host`** is ignored unless the request comes from a trusted proxy (`FLEET_TRUSTED_PROXIES`), so a client cannot claim the other hostname.
- **Production** refuses to boot without both hostnames.
- **Development** uses `localhost` for the dashboard and `agent.localhost` for the API, both on port 3000.

**Operators sign in with Google** (DEC-06). There are no passwords and no sign-up.

- Only a Google-verified email on the allowlist can sign in. Anyone else is refused without a record being created.
- The allowlist is re-checked on every request, so removing an email signs that operator out on their next request.
- Sessions are server-side (`operator_sessions`). The encrypted cookie holds only a random token, and the table stores its digest. Signing out revokes the session, so a saved copy of the cookie stops working.
- Every dashboard controller requires sign-in unless it calls `allow_unauthenticated_access`. A spec enumerates the routes to enforce this.

```sh
bin/rails operators:allow EMAIL=you@example.com      # the first operator, and any later one
bin/rails operators:list
bin/rails operators:disallow EMAIL=you@example.com
```

Google OAuth needs a web client in Google Cloud. Its authorised redirect URI is `https://<dashboard host>/auth/google_oauth2/callback`, or `http://localhost:3000/auth/google_oauth2/callback` for development.

| Setting | Default | |
|---|---|---|
| `FLEET_DASHBOARD_HOST`, `FLEET_AGENT_HOST` | required in production | The two hostnames above |
| `FLEET_TRUSTED_PROXIES` | loopback only | Comma-separated addresses or CIDRs of the tunnel connector and the agent TLS proxy. Only these may set `X-Forwarded-Host`, `X-Forwarded-For`, `Client-IP` and `Forwarded`; the host guard drops those headers from anyone else, so client addresses used for rate limits cannot be spoofed |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | required in production | Google OAuth web client |
| `FLEET_SESSION_IDLE_MINUTES` | `120` | Sign out after this long without a request |
| `FLEET_SESSION_ABSOLUTE_HOURS` | `12` | Sign out this long after signing in, however active |

## Dashboard

Server-rendered Hotwire views built from the approved mockups in `../docs/mockups/phase-1/` (P1-DASH-FLEET). The styles are `app/assets/stylesheets/application.css`, with self-hosted fonts (OFL licences beside them in `app/assets/fonts/`).

- **Fleet list** (`/`): counts by status, search, tag and status filters, and sortable columns. All of it lives in the query string, so a view can be bookmarked. `FleetList` builds the list in two queries whatever the fleet size; retired hosts are never listed or counted.
- **Host detail** (`/hosts/:id`): current inventory (unreadable facts show "Not available" with the agent's warning), inventory history with the changed fields (`InventoryDiff`), enrollment and credential state, status history, and the host's audit entries. Operator actions arrive with P1-DASH-ACTIONS.
- **Settings** (`/settings`): the liveness thresholds.
- **Escaping.** Everything a host or operator supplied is rendered through Rails' escaping; nothing is marked `html_safe`. Inventory meters use width classes rather than inline styles.

### Live updates

Status changes reach open pages within seconds, over Turbo Streams on Action Cable (Solid Cable):

- Code that changes what the fleet shows calls `FleetBroadcast.hosts_changed(ids)` inside its transaction: heartbeat status changes, liveness evaluation, enrollment transitions, edits, and the first inventory. `FleetBroadcastJob` is enqueued only after the outermost transaction commits.
- The job sends a Turbo **page refresh**. Each open fleet list or host page re-requests itself with its own filters and sort, and morphs the result in, so list membership, order, counts, empty states, and the host header always agree with a fresh load. The stream element is `data-turbo-permanent`, so the subscription survives the morph, and a filter form the operator is editing is left alone (`keep_edits_controller.js`).
- `/cable` is mounted only on the dashboard hostname. A connection needs a live operator session from the dashboard cookie (`ApplicationCable::Connection`); it is rechecked every 30 seconds and closed at once on sign-out. Production accepts handshakes only from `https://$FLEET_DASHBOARD_HOST`.
- When the connection drops, the top bar reads "Reconnecting" and a banner warns that statuses may be out of date. After any interruption, however short, the page refreshes itself once to catch up, since broadcasts are not replayed. A first connection that never succeeds also ends in the banner (`app/javascript/controllers/live_status_controller.js`).

## Agent API and enrollment

The agent API lives under `/api/v1` (`app/controllers/api/v1`) on the agent hostname. Its contract is `../docs/api`: the conventions, error codes, schemas and examples.

- **Validation.** Request bodies are validated at runtime against `../docs/api/schemas`, so those files must be present wherever the server runs:
  - The path comes from `FLEET_API_SCHEMAS_DIR`, which defaults to `../docs/api/schemas`.
  - The server refuses to boot without the schemas.
- **Request guard.** `lib/middleware/agent_api_request_guard.rb` caps `/api/` bodies at 1 MB and stops Rails parsing or logging agent JSON. `Api::V1::BaseController` then reads, size-checks (per endpoint) and validates the raw body, and renders every failure as the documented error envelope.
- **Authenticated endpoints** inherit from `Api::V1::AuthenticatedController`. The host is always `current_host`, from the credential; never look a host up from the request. A spec enforces both rules.

| Setting | Default | |
|---|---|---|
| `FLEET_API_SCHEMAS_DIR` | `../docs/api/schemas` | Where the JSON Schemas are read from |
| `FLEET_MINIMUM_AGENT_VERSION` | `0.1.0` | Older agents get `426 agent_version_unsupported` |
| `FLEET_API_RATE_LIMIT_PER_MINUTE` | `120` | Per credential, across authenticated endpoints |
| `FLEET_ENROLL_RATE_LIMIT_PER_MINUTE` | `10` | Per client address, on `POST /api/v1/enroll` |
| `FLEET_ENROLLMENT_TOKEN_TTL_HOURS` | `24` | Enrollment token lifetime |

### Onboarding

The default way to enroll (DEC-17). The installer starts a request and an operator approves it; nothing becomes a host until then.

- **`POST /api/v1/onboarding`** is unauthenticated, but served only on the agent hostname and limited per client address. It is also capped in how many requests may await approval, in total and per address. It creates an `onboarding_requests` row, not a host. The response carries:
  - a **device code**, which only the installer holds and which is stored as a digest;
  - a **user code**, such as `WDJB-MJHT`, for the operator to match with the terminal;
  - the approval URL on the dashboard.
- **Deciding.** An operator approves (`Onboarding::Approve`), either as a new host with the fields they enter or as the re-enrollment of a host they choose, or rejects (`Onboarding::Reject`). Both are audited. The approval page arrives with P1-DASH-ACTIONS (#10).
- **`POST /api/v1/onboarding/token`** is polled with the device code:
  - `202` while the request waits;
  - `429` when polled faster than the interval;
  - `403 onboarding_rejected` after rejection;
  - `410 onboarding_expired` when the code is unknown, expired, or already used;
  - `201` once approved, with the credential, exactly once. The host is created, or re-enrolled, in that same transaction.
- **Cleanup.** Requests expire after 10 minutes and are deleted a day later by `OnboardingPruneJob` (`config/recurring.yml`).

| Setting | Default | |
|---|---|---|
| `FLEET_ONBOARDING_TTL_MINUTES` | `10` | How long a request waits for approval |
| `FLEET_ONBOARDING_POLL_SECONDS` | `5` | Minimum time between polls |
| `FLEET_ONBOARDING_MAX_OPEN`, `FLEET_ONBOARDING_MAX_OPEN_PER_ADDRESS` | `50`, `5` | Requests awaiting approval, in total and per client address |
| `FLEET_ONBOARDING_RATE_LIMIT_PER_MINUTE` | `10` | Starts per client address |
| `FLEET_DASHBOARD_URL` | `https://$FLEET_DASHBOARD_HOST` | Base of the approval URL, if the dashboard uses another scheme or port |

### Pre-registration

Until the dashboard's host actions arrive (P1-DASH-ACTIONS), hosts are created and enrolled from the command line. Each task prints the enrollment token once, and only its digest is stored.

```sh
bin/rails hosts:create DISPLAY_NAME="Media server" VM_HOSTNAME=vm-01.example.lan TAGS=media,lab
bin/rails hosts:enroll_token VM_HOSTNAME=vm-01.example.lan   # re-enrollment; or HOST_ID=...
```

`VM_HOSTNAME` is used instead of `HOSTNAME` because shells set `HOSTNAME` to the local machine's name.

- **Re-enrollment.** Issuing a token for an active or revoked host moves it to `pending`. An active host's old credential keeps working until the new token is redeemed, then stops immediately. Issuing a token also expires any earlier unredeemed token for the host.
- **Revocation.** `Host#revoke!` and `Host#retire!` revoke the host's credential in the same transaction.

### Docker image

The image needs the schemas too, so build it from `cmdb/` with `docs/api` as a named build context:

```sh
docker build --build-context api=../docs/api -t cmdb .
```

## Secrets

- `config/master.key` is generated locally and **never committed** (it is ignored). `config/credentials.yml.enc` is committed but cannot be read without that key. Back the key up with the database backup (NFR-2): a restored database without the key is not enough to run production.
- A fresh clone does not have the key. Development and test do not need it; to create your own credentials for production, run `bin/rails credentials:edit` (this generates a new key and file).
- Logs filter credentials, tokens, authorization headers, and session material (`config/initializers/filter_parameter_logging.rb`, covered by `spec/config/filter_parameters_spec.rb`).

## Layout notes

- `Dockerfile` is the Rails production image. The deployment stack (Compose, Cloudflare tunnel, private agent hostname) is added by its own issue.
- Kamal, Action Mailer, Action Mailbox, Action Text, Active Storage, and jbuilder were deliberately not generated.
