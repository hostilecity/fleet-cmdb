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

## Secrets

- `config/master.key` is generated locally and **never committed** (it is ignored). `config/credentials.yml.enc` is committed but cannot be read without that key. Back the key up with the database backup (NFR-2): a restored database without the key is not enough to run production.
- A fresh clone does not have the key. Development and test do not need it; to create your own credentials for production, run `bin/rails credentials:edit` (this generates a new key and file).
- Logs filter credentials, tokens, authorization headers, and session material (`config/initializers/filter_parameter_logging.rb`, covered by `spec/config/filter_parameters_spec.rb`).

## Layout notes

- `Dockerfile` is the Rails production image. The deployment stack (Compose, Cloudflare tunnel, private agent hostname) is added by its own issue.
- Kamal, Action Mailer, Action Mailbox, Action Text, Active Storage, and jbuilder were deliberately not generated.
