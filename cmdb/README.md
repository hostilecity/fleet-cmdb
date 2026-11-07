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

To run the whole system on your machine, including a real agent against this server, see [docs/operations/running-locally.md](../docs/operations/running-locally.md).

From this directory, create your local settings file first (`.env` is ignored by git and loaded in development and test by `dotenv-rails`):

```sh
cp .env.example .env   # then fill in the values
```

Then:

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

The test environment uses two databases, `cmdb_test` and `cmdb_test_queue` (Solid Queue's tables, so specs can run and fail real jobs); `DATABASE_URL` and `QUEUE_DATABASE_URL` override their names, for example to run several checkouts side by side. Tests never reach the network (WebMock blocks everything except localhost). Put factories in `spec/factories/` and shared helpers in `spec/support/`.

Specs run in random order. To reproduce a failure, rerun with the seed RSpec printed: `bundle exec rspec spec/path_spec.rb:12 --seed 1234`. In GitHub Actions, each failing example, any error outside an example, and any failed `bin/ci` step also becomes an error annotation on the pull request (with the seed and the rerun command), because the job log cannot always be read. The workflow keeps the full `bin/ci` log and RSpec's JSON results as the `bin-ci-log` artifact.

Specs that use threads (`spec/services/*_concurrency_spec.rb`) run outside the test transaction. Each thread loads its own records on its own connection: Active Record objects are not thread-safe, and sharing one between threads made a spec fail intermittently (#69).

### Fleet simulator and load check

`bin/simulate-fleet` runs fake hosts against a running development server through the real agent API: seed data, the NFR-3 load check (`--load-check`), and a scaled-down AC-1.2 liveness check (`--liveness-check`). See [docs/operations/fleet-simulator.md](../docs/operations/fleet-simulator.md).

## Databases

Development uses `cmdb_development` plus `cmdb_development_cache`, `_queue`, and `_cable`, mirroring production's layout. Tests use a single `cmdb_test` database with the test adapters for jobs, cache, and cable.

Recurring jobs are declared in `config/recurring.yml` and run by Solid Queue's scheduler. Later issues add their jobs there.

### Health and backups

- `GET /health` (agent hostname and localhost, unauthenticated) answers 200 `{"status":"ok"}` or 503 and lists the checks `database`, `releases`, and `backup` as `ok` or `failing`, nothing more. `releases` fails when the newest release's binary is missing from `FLEET_RELEASES_DIR` or has a different size than its row; `backup` fails when `FLEET_BACKUP_STATUS_FILE` (default `storage/backup/last_success`) is missing or older than `FLEET_BACKUP_MAX_AGE_HOURS` (default 26). `/up` stays the container liveness check.
- `bin/rails backup:verify_restore` is the checking half of the restore drill. The procedure, scripts, and what else must be backed up are in [docs/operations/backup-and-restore.md](../docs/operations/backup-and-restore.md).

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

### Config fact manifest

`GET /api/v1/manifest/config` (FR-2.1, P2-S01) publishes the facts an agent may report: `config/fact_manifest.yml`, loaded and validated as a whole by `lib/config_manifest.rb` (a manifest that does not validate stops the first use, with every problem listed), served to an active host with a strong `ETag`. Config reports (P2-S02) are validated against the same facts. To add a fact, see [docs/operations/config-facts.md](../docs/operations/config-facts.md).

### CIS-aligned rules

Rules (FR-2.2, DEC-10, DEC-12, P2-S04) are data in a YAML or JSON file the operator controls; the format is in [docs/api/rules](../docs/api/rules/README.md).

- **Import.** `bin/rails rules:import FILE=rules.yml` checks the whole file (`CisRules::RuleFile`: safe YAML, the JSON Schema, then each rule against the fact manifest) and writes nothing if anything is wrong, listing every problem. `DISABLE_MISSING=1` disables enabled rules the file does not list; otherwise they are left alone. `bin/rails rules:list` shows each rule's key, version, flag, severity, and fact. Imports are serialised and audited with the system actor.
- **Storage.** `cis_rules`: the stable key, the enabled flag, and the current version. `cis_rule_versions`: one row per definition, never changed (`readonly?`), numbered from 1; an import creates one only when the definition's content hash changes.
- **Audit.** `rule.created`, `rule.edited` (each changed field before and after, and the version), `rule.enabled`, `rule.disabled`; the audit page names the rule by its key.
- **Evaluation.** `CisRules::Evaluator.call(rule, facts, os)` (P2-S05) is a pure function returning `pass`, `fail`, `not_applicable`, or `not_readable`, with the observed value or the reason. It never runs rule data as code (a spec checks the rule code's tokens); patterns are anchored and time-limited.
- **Results** (P2-S06). `CisEvaluation.evaluate!(host_ids, rule_ids: nil)` evaluates each host's latest config snapshot, with the os from its inventory, and stores:
  - `cis_results`: one row per host and rule with the result (`pass`, `fail`, `not_applicable`, `not_readable`, or `not_evaluated`), the observed value, the reason, and the rule version and snapshot used. A disabled rule, and every rule on a host with no config report, is `not_evaluated`.
  - `cis_result_changes`: a row only when a result changes (from, to, when, version, snapshot), so running evaluation again writes nothing new. Pruned by `Retention`; current results never are.
  - Each host is evaluated in its own transaction under its row lock, the lock agent writes take, so it never sees half of a config report.
- **When it runs.** `CisEvaluationJob` runs for a host after a new config snapshot and when its operating system changes, and for a rule on every host after it is created, edited, enabled, or disabled. All enqueued once the transaction commits, so a rule import re-evaluates without agents.
- **Compliance.** `CisCompliance.for_host(id)` and `for_hosts(ids)` count passed, failed, not applicable, not readable, and not evaluated (a rule without a result yet counts as not evaluated, so the counts add up to the number of rules).
- **Image.** The schema is read at runtime from `FLEET_RULES_SCHEMA_DIR` (default `../docs/api/rules`); the Docker image copies `docs/api/rules` from the `api` build context.

### Config reports

`POST /api/v1/reports/config` (FR-2.1, DEC-07, DEC-08, P2-S02) takes the host's configuration facts keyed by the fact keys of the config fact manifest, as JSON or gzip, with the same limits as package reports (4 MiB of JSON, 1 MiB compressed). The response carries the server's `manifest_version`, so an agent with an older copy fetches the manifest again.

- **Validation.** The body is validated against `docs/api`; `lib/agent_api/config_report.rb` then checks each `ok` value against its fact in the manifest (type, length, range, list size) and refuses a NUL anywhere in a value. Any problem refuses the whole report, with a pointer per fact, and nothing is written. A manifest version newer than the server's is refused; a fact key the manifest does not have is ignored and logged, and kept in `ignored_keys`.
- **Missing facts.** Every manifest fact the report leaves out is stored as `missing`, with a reason: "not included", or, for a fact added after the report's manifest version, which version added it. Unordered lists are stored sorted, so a reordering is no change.
- **Storage.** `ConfigRecorder` stores a valid report under the host row lock:
  - `config_report_receipts`: report ids already processed. A retried report is answered `duplicate: true` and changes nothing.
  - `host_configs`: the current facts (`{key => {state, value, reason}}`, the form `CisRules::Evaluator` reads), counts per state, the content hash, the report's manifest version, and the ignored keys, updated on every report.
  - `config_snapshots`: the facts as they were, written only when the content hash changes. Retention keeps the newest per host.
- **Diff.** `ConfigDiff.between(older, newer)` (or `ConfigDiff.for(snapshot)`) lists facts added, removed, and changed, where a change of state or reason alone (ok to unreadable) counts.
- **Evaluation.** A new snapshot enqueues `CisEvaluationJob` for the host (P2-S06).

### Package reports

`POST /api/v1/reports/packages` (FR-2.3, DEC-07, P2-S08) takes every installed package, as JSON or gzip (`Content-Encoding: gzip`): at most 4 MiB of JSON, sent plain or once decompressed, and 1 MiB compressed. `AgentApiRequestGuard` lets this path's plain bodies past its general 1 MiB limit (`UNCOMPRESSED_LIMITS`).

- **Validation.** The body is validated against `docs/api`; `lib/agent_api/package_report.rb` then refuses a package listed twice for one architecture. `manager: unsupported` carries a reason and no packages. A version dpkg would refuse is stored as reported; matching treats it as not evaluated.
- **Storage.** `PackageRecorder` stores a valid report under the host row lock:
  - `package_report_receipts`: report ids already processed. A retried report is answered `duplicate: true` and changes nothing.
  - `host_package_sets`: the manager (or that it is unsupported, and why), the package count, the content hash, and warnings, updated on every report.
  - `host_packages`: one row per installed package, replaced when the set changes; indexed by source package for matching.
  - `package_snapshots`: the whole set as `[name, architecture, version, source]` rows, written only when the content hash changes. Retention keeps the newest per host.
- **Diffs.** `PackageDiff.between(older, newer)` lists installed, removed, and changed packages; a change is an upgrade or a downgrade by dpkg's order (`lib/package_versions`, FR-2.4). With an unsupported manager on either side the set is unknown, so the diff is not available (`available?` is false) rather than everything removed or installed.

### Report requests

An operator can ask a host's agent for fresh config, inventory, and package reports (FR-2.1, DEC-13, P2-S03) with "Request fresh reports" on the host page (`POST /hosts/:id/request_reports`, CSRF-protected, no confirmation page since it changes nothing on the VM). `ReportRequests` is the only code that changes `report_requests`:

- **Request.** One `report_requests` row per type, pending, with the operator and the server time, audited as `host.report_requested`. Only an active host can be asked. A partial unique index allows one pending request per host and type.
- **Rate limit.** One request per host and type every 5 minutes (`ReportRequests::COOLDOWN`), whatever happened to the previous one; a type still pending from an older request is left as it is. The page says when to try again.
- **Directive.** Every heartbeat carries the outstanding types as `"report_request": {"types": [...]}` (DEC-20) until each request ends. The first heartbeat that carries a request records `sent_at` (server clock) and its own `agent_time` as `delivered_agent_time` (agent clock). A host with nothing outstanding costs one indexed SELECT. An agent that ignores the directive is unaffected.
- **Satisfied.** `InventoryRecorder`, `PackageRecorder`, and `ConfigRecorder` call `ReportRequests.satisfy!` for every new report, changed or not. A report clears the request only when a heartbeat has delivered it and the report's `collected_at` is later than `delivered_agent_time`, recording the report id. Both times are the agent's clock, so clock skew cancels out and network delay can only make the check stricter; the one window is a report collected while the delivering heartbeat was in flight. A report from before delivery, or before any heartbeat carried the request, leaves it pending. A retried (duplicate) report clears nothing.
- **Expired.** A request no report answers within an hour (`ReportRequests::TTL`) stops being sent, and `ReportRequestExpiryJob` (every minute, `config/recurring.yml`) marks it `expired` with `expired_at`. Ended requests are kept for the host page and pruned by Retention after the retention window.

### Advisory data

Vulnerability advisories (FR-2.4, DEC-11, P2-S10, P2-S13) are OSV records for the fleet profile's ecosystems: `Ecosystems` (`app/models/ecosystems.rb`) maps an inventory's os id and version to one, and only `debian` `13` → `Debian:13` is listed (DEC-01). Records for other ecosystems are skipped.

- **Import** (`Advisories::Import`, `app/services/advisories`), from a `.json` file, a directory of them, or a `.zip` archive such as OSV's `all.zip`. Each run is one transaction, so input that cannot be read at all imports nothing.
  - **Idempotent** by advisory id and `modified`: the same or an older record changes nothing, and a newer one replaces the advisory and its packages.
  - **Malformed records** are skipped and reported with where they were and why, and the valid records import.
  - **Limits:** each document is read to at most 2 MiB, and an archive may be at most `FLEET_ADVISORY_MAX_DOWNLOAD_MB` and hold at most a million documents and 8 GiB of JSON.
  - **Stored:** text has control characters removed and a length cap, and only `http` and `https` reference URLs are kept.
  - **Severity** is normalised to critical, high, medium, low, or unknown by the rule in `Advisories::Severity` (a CVSS v3 score, then a severity word, then a Debian urgency), keeping the raw value.
  - **Withdrawn advisories** are kept and marked. A *full* import (the refresh, or `FULL=1`) is the whole data set for its ecosystems, so an advisory it does not contain is marked withdrawn as `absent`: OSV moves withdrawn records out of an ecosystem's archive. That sweep is skipped when any record was malformed, and spares advisories newer than the newest record in the import.
  - **Audit:** every import is audited (`advisory.imported`, `advisory.import_failed`) with the operator or the system as actor, the source, and the counts.
- **Storage.** `advisories` holds each advisory at its newest version. `advisory_packages` holds one row per advisory, ecosystem, and source package, with the OSV `ECOSYSTEM` ranges' events, indexed by ecosystem and package for matching. `advisory_imports` records every import, which is how freshness is known.
- **Scheduled refresh.** `AdvisoryFeedRefreshJob` runs every 6 hours in production (`config/recurring.yml`).
  - It downloads `FLEET_ADVISORY_FEED_URL` over HTTPS with the certificate verified, within 15 minutes for the whole exchange, and imports it as a full data set. The request is conditional (`If-None-Match`, `If-Modified-Since`) unless the last download had malformed records.
  - A failure of any kind is retried with backoff. After the last attempt it is recorded and audited, and the job fails, so it shows on the failed-jobs banner and in `/health`.
  - Errors and logs name only the feed's host, never its path, query, or token.
- **Freshness.** Data is as fresh as the last successful full import with records for the ecosystem. The fleet page shows when each ecosystem's data was last updated, and a warning when it is older than `FLEET_ADVISORY_MAX_AGE_HOURS` or was never refreshed. A partial import adds data but does not count.

```sh
bin/rails advisories:import FILE=path/to/all.zip FULL=1   # a complete archive, for a server without internet access
bin/rails advisories:import FILE=path/to/DSA-5800-1.json  # one advisory (or a directory of them)
bin/rails advisories:refresh                              # run the scheduled refresh now
bin/rails advisories:status                               # freshness per ecosystem and the last import
```

| Setting | Default | |
|---|---|---|
| `FLEET_ADVISORY_FEED_URL` | `https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip` | The OSV archive the refresh downloads (Debian's covers every release; only `Debian:13` is kept). HTTPS only, or empty to turn the refresh off |
| `FLEET_ADVISORY_FEED_TOKEN` | none | Sent as a bearer token, for a mirror that needs one; also read from credentials (`advisories.feed_token`). Never logged or shown |
| `FLEET_ADVISORY_MAX_DOWNLOAD_MB` | `512` | The largest archive downloaded or imported |
| `FLEET_ADVISORY_MAX_AGE_HOURS` | `48` | Older data shows a warning on the dashboard |

### Vulnerability findings

`VulnerabilityMatcher` (P2-S11, FR-2.4, AC-2.4) matches each host's installed packages against the advisories for its ecosystem.

- **Matching.**
  - It matches on source package name, or the binary name when dpkg records no source.
  - It applies OSV's range algorithm, `limit` included, with dpkg's version order (`PackageVersions`), never string comparison. A finding's fixed version is the fix of the range the installed version is in.
- **Findings.** `vulnerability_findings` holds one finding per host, advisory, and installed binary package (name and architecture), so each binary built from an affected source has its own.
  - **States:** `open`, `resolved` with a resolution (`fixed`, `removed`, `withdrawn`, or `not_affected`), and `reopened` when the condition returns, for example after a downgrade or a reinstall.
  - **Timestamps:** `first_seen_at`, `resolved_at`, and `reopened_at`.
- **Not evaluated.** `host_vulnerability_evaluations` records each host's last run.
  - **A whole host** is "not evaluated", with the reason, when it has no inventory, is on a distribution outside the fleet profile, has no package report, has an unsupported package manager, or has no advisory data for its ecosystem. Its findings are left as they were.
  - **One package** whose version, or whose advisory's version, dpkg cannot parse is listed as not evaluated, and its finding is left as it was.
- **When it runs.** `VulnerabilityMatchJob` runs after each commit that adds a package snapshot (for that host) and after each import (for the packages it changed, plus hosts not yet evaluated). Agents are not involved.
  - **Idempotent:** running it again changes nothing.
  - **Concurrency:** each host is matched in its own short transaction under its row lock (`FOR UPDATE`), the lock package reports take, so it never sees half of a report.
  - **Cost:** a fixed number of queries per host whatever its package count. 50 hosts by 2,000 packages take about 5 s.

```sh
bin/rails vulnerabilities:match   # match every host now
```

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
- **Audit log** (`/audit`, P1-AUDIT-PAGE): every audit entry, newest first, read-only. Filters (actor type and actor, action, target host, date range in whole UTC days, and "hide sign-ins") and the page position live in the query string. Pages are keyset ranges on `(occurred_at, id)`, 50 entries each, with a readable cursor (`before=2026-10-14T10:02:31.482113Z,4127`), so a page costs the same however long the log grows. `AuditLog` builds the query; the host page's "All entries for this host" link filters by host id. Onboarding approvals and rejections target the request; the log links a request to its host through the host's "Enrolled" entry and a re-enrollment approval's `host_id` (requests are pruned, the log is not), using two small partial indexes.
- **Settings** (`/settings`): the liveness thresholds.
- **Agents** (`/agents`, P1-RELEASES): imported releases, which key signed each, and how many hosts in the fleet run it; imports from GitHub and by upload (below). Rollouts join this page with P1-UPDATES.
- **Install an agent** (`/agents/install`, P1-D08): the exact commands for the newest imported release that is not a pre-release (or `?version=`): download from the agent hostname, check the SHA-256, run `fleet-agent install`, then approve; and the pre-registered-token and cloud-init variants. Every URL and checksum on the page comes from the one release shown. A pre-registered host's token page shows the same download and check.
- **Host actions** (P1-D04): pre-register (the one-time token and install commands appear only in the response to that POST, marked `no-store`), edit, and, each behind a confirmation page and a CSRF-protected POST: revoke, re-enroll (instructions for `fleet-agent install --reenroll`, or a new one-time token), and retire (the hostname must be typed).
- **Onboarding approval** (P1-D07, `/onboard`): the installer's link opens `/onboard/<code>`, and signing in returns there. The page shows the code to match, what the VM reported, and, when the machine ID or hostname matches existing hosts, a choice between re-enrolling one and adding a new host. The code box answers unknown, expired, and decided codes alike. Code lookups are rate-limited per operator, and `/onboard/<code>` links that find nothing count against the same limit. The fleet page says while VMs are waiting, and the lists and outcomes update live.
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
| `FLEET_MINIMUM_AGENT_VERSION` | `0.1.0` | Older agents get `426 agent_version_unsupported`, except on heartbeats, update results, and release downloads (the update path) |
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

### Agent releases

Signed agent releases ([docs/releases.md](../docs/releases.md), ADR 0018, ADR 0021) are imported into the server, which serves them to installers and agents on the agent hostname (P1-RELEASES).

- **Verification** (`app/services/releases`): the same checks as the agent (`agent/src/release`), in the same order, with Ruby's OpenSSL (Ed25519 and BLAKE2b-512; no extra gem). The minisign signature and its global signature over the trusted comment must verify against a configured release key, current or next, in minisign's pre-hashed mode; then the manifest must follow its format (strict SemVer without build metadata, the one target, a SHA-256, a size of 1 byte to 64 MiB, no other fields); then the binary must have exactly that size and SHA-256. A release that fails is refused with the reason. This is defence in depth: agents verify independently.
- **Importing.** From GitHub: an operator enters a version on the Agents page and `AgentReleaseImportJob` downloads the tag `agent-v<version>`'s assets from `https://github.com/$FLEET_RELEASE_REPOSITORY/releases/download/...` (the server needs outbound HTTPS to `github.com` and GitHub's download host). The signature is checked before the binary is downloaded. An unreachable GitHub is retried with backoff, then reported. `agent_release_imports` shows each import's outcome on the page. By upload: the three files of a GitHub release, verified while the operator waits, for a server without internet access.
- **Audit.** Every import (`release.imported`), refusal (`release.import_refused`), and failed GitHub import (`release.import_failed`) is audited with the operator as actor, with the version and the reason.
- **Storage.** `agent_releases` keeps the exact manifest and signature bytes; the binary is a file in `FLEET_RELEASES_DIR` (a persistent volume; Active Storage is not used), written to a staging file and renamed into place once verified. Releases are immutable, and never deleted while a host in the fleet runs them: the model and the `agent_releases_guard` trigger refuse it. A rollout holds a restricting foreign key to its release too (P1-UPDATES).
- **Downloads.** `GET /api/v1/releases/<version>/manifest`, `signature`, and `binary` on the agent hostname only (`docs/api/README.md`): no credential, limited per address, never `426`, with `ETag`, `Content-Length`, and byte ranges so a broken download resumes.

| Setting | Default | |
|---|---|---|
| `FLEET_RELEASE_KEY_CURRENT`, `FLEET_RELEASE_KEY_NEXT` | none | The release public keys: the two lines of `agent/release-keys/current.pub` and `next.pub`, or only their base64 key line. A malformed key, or a next key without a current one, stops the boot. With no current key every import is refused. The server never holds a private key |
| `FLEET_RELEASES_DIR` | `storage/releases` | Where release binaries are kept. Mount a persistent volume here |
| `FLEET_RELEASE_REPOSITORY` | `hostilecity/fleet-cmdb` | The GitHub repository releases are imported from |
| `FLEET_RELEASE_DOWNLOAD_RATE_LIMIT_PER_MINUTE` | `60` | Release downloads per client address |
| `FLEET_ROLLOUT_SPREAD_SECONDS` | `300` | Window over which opening a rollout stage spreads the update directive (P1-UPDATES) |
| `FLEET_UPDATE_CONFIRMATION_TIMEOUT_MINUTES` | `30` | A host sent the update directive that has not reported by then is `unconfirmed`, which halts the rollout |

### Docker image

The image needs the agent API schemas and the rule file schema too, so build it from `cmdb/` with `docs/api` as a named build context:

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
