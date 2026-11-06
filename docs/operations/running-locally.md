# Running fleet-cmdb locally

How to run the tests, the server, a simulated fleet, and a real agent on your own machine, without deploying anything. The test, simulator, and agent steps were run as written on Linux; the macOS container steps for the agent are marked as not yet verified.

| You want to | Section |
|---|---|
| Run the test suites | [1. Tests](#1-tests) |
| Use the dashboard | [2. The server](#2-the-server) |
| See a fleet of hosts | [3. A simulated fleet](#3-a-simulated-fleet) |
| Run the real agent against your server | [4. A real agent](#4-a-real-agent) |

## Before you start

- **Server:** Ruby 3.4.10 through chruby and PostgreSQL, as in [`cmdb/README.md`](../../cmdb/README.md#development-environment-macos), then `bin/setup --skip-server` in `cmdb/`.
- **Local settings:** `cp .env.example .env` in `cmdb/`, then fill in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` (section 2). The app reads `cmdb/.env` whenever it starts (`bin/dev`, `bin/rails`, `bin/simulate-fleet`, and Puma in section 4), so settings in this guide go there rather than on the command line; a value set in the shell still wins. It is ignored by git; never commit it.
- **Agent:** [rustup](https://rustup.rs); it installs the toolchain pinned in `agent/rust-toolchain.toml` on first use. The agent runs only on Linux; on macOS it runs in a Docker container (section 4).
- **Certificates:** `openssl` (installed on macOS and most Linux systems).

## 1. Tests

```sh
cd cmdb && bin/ci                      # rubocop, audits, brakeman, and the full RSpec suite (what CI runs)
cd agent && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
ruby docs/backlog/import.rb check      # the backlog and specs, from the repository root
```

`bin/ci` needs PostgreSQL running. A subset is quicker: `NO_COVERAGE=1 bundle exec rspec spec/requests` in `cmdb/`. The agent builds only on Linux; on macOS, run its checks in a Linux container as in [`agent/README.md`](../../agent/README.md#build-and-check).

## 2. The server

```sh
cd cmdb
bin/rails operators:allow EMAIL=you@example.com
bin/dev
```

Open <http://localhost:3000> and sign in with that Google account. Sign-in needs a Google OAuth web client, with its ID and secret in `cmdb/.env`, whose authorised redirect URI is `http://localhost:3000/auth/google_oauth2/callback` ([`cmdb/README.md`](../../cmdb/README.md#hostnames-and-operator-sign-in)). `bin/dev` also runs the background jobs, including the liveness check that turns silent hosts stale and offline.

## 3. A simulated fleet

To fill the dashboard without any VMs, run the simulator in another terminal while `bin/dev` runs:

```sh
bin/simulate-fleet --hosts 20 --duration 30m
```

Enrolling is rate-limited per address, so with the defaults the simulator waits a few minutes for 20 hosts. To skip that, add `FLEET_ENROLL_RATE_LIMIT_PER_MINUTE=100` to `cmdb/.env` and restart `bin/dev`. The test environment sets its own limits, so this does not change the test suite.

The hosts (`sim-001` and on) report while it runs and go stale and then offline after it stops. `--load-check` and `--liveness-check` run the NFR-3 and AC-1.2 checks. See [fleet-simulator.md](fleet-simulator.md).

## 4. A real agent

The agent talks to its server only over HTTPS, at the agent hostname, and its config cannot turn certificate checks off (NFR-1). Locally, that means a throwaway certificate authority, Puma serving TLS on a second port, and an agent config that trusts the authority. The development server answers the agent API on `agent.localhost`.

**a. A certificate for `agent.localhost`**, valid for 30 days, from the repository root:

```sh
mkdir -p ~/fleet-local
bash -c '. agent/scripts/update-test-lib.sh && make_certs ~/fleet-local agent.localhost 30'
```

This writes `ca.pem` (the authority the agent trusts) and `cert.pem` and `key.pem` (the server's). They are for this machine only; nothing in `~/fleet-local` belongs in the repository.

**b. The server, on HTTP for the dashboard and HTTPS for the agent.** Instead of `bin/dev`, from `cmdb/`:

```sh
SOLID_QUEUE_IN_PUMA=1 bundle exec puma -C config/puma.rb \
  -b tcp://127.0.0.1:3000 -b "ssl://127.0.0.1:3443?key=$HOME/fleet-local/key.pem&cert=$HOME/fleet-local/cert.pem"
```

The dashboard stays on <http://localhost:3000>; the agent API is at `https://agent.localhost:3443`. Logs go to `log/development.log` rather than the terminal. Check it, and add `127.0.0.1 agent.localhost` to `/etc/hosts` if the name does not resolve:

```sh
curl --cacert ~/fleet-local/ca.pem https://agent.localhost:3443/up
```

**c. A host and its credential.** Register the host and redeem its one-time token, as `fleet-agent install` does on a VM:

```sh
cd cmdb && bin/rails hosts:create DISPLAY_NAME=local-agent VM_HOSTNAME=vm-01.example.lan
read -rs TOKEN       # paste the token it printed (shown once), then Enter
curl -s --cacert ~/fleet-local/ca.pem https://agent.localhost:3443/api/v1/enroll -H 'Content-Type: application/json' \
  -d "{\"schema_version\":1,\"agent_version\":\"0.1.0\",\"token\":\"$TOKEN\",\"hostname\":null,\"machine_id\":null}"
```

The answer's `credential` is the host's permanent credential: keep it out of shell history and the repository. The dashboard's **Pre-register host** page gives a token too.

**d. The agent's config**, `~/fleet-local/config.toml`. It must belong to you and be readable only by you (`chmod 600`), or the agent refuses it. Paths must be absolute:

```toml
server_url = "https://agent.localhost:3443"
credential = "<the credential from step c>"
ca_file = "/home/you/fleet-local/ca.pem"
state_dir = "/home/you/fleet-local/state"

[heartbeat]
interval_seconds = 10
min_seconds = 10

[inventory]
interval_seconds = 60
min_seconds = 60
```

The short intervals are for watching it work; leave them out for the defaults (60 s and 15 minutes).

**e. Run it** (Linux), from `agent/`:

```sh
cargo build --release
target/release/fleet-agent check-config --config ~/fleet-local/config.toml
target/release/fleet-agent run --config ~/fleet-local/config.toml
```

It logs the startup inventory report and its first accepted heartbeat, and `local-agent` turns online in the dashboard with this machine's inventory. `Ctrl-C` stops it; the host then turns stale and offline. It also logs that it cannot update itself: updates need the installed layout under `/usr/lib/fleet-agent`, which only `fleet-agent install` creates on a VM.

**On macOS** (not yet verified): the agent does not build on macOS, so build and run it in Linux containers instead of step e. Use container paths in the config (`ca_file = "/fleet-local/ca.pem"`, `state_dir = "/fleet-local/state"`), and from the repository root:

```sh
docker run --rm -v "$PWD/agent":/src -w /src -e CARGO_TARGET_DIR=/src/target/linux \
  -v fleet-agent-cargo:/usr/local/cargo/registry rust:1.97-bookworm cargo build --release
docker run --rm -it --add-host agent.localhost:host-gateway \
  -v "$PWD/agent/target/linux/release/fleet-agent":/usr/local/bin/fleet-agent:ro -v "$HOME/fleet-local":/fleet-local \
  debian:13 fleet-agent run --config /fleet-local/config.toml
```

The agent checks that the config belongs to the user it runs as (root in the container), so if it refuses the config, copy it into the container's own filesystem with that ownership. If the container cannot reach the server, bind Puma's TLS port to `0.0.0.0` instead of `127.0.0.1`, which also exposes it to your network while it runs.

## Cleaning up

Stop the server and the agent, then delete `~/fleet-local` (the certificates, the credential, and the agent's state). Retire the hosts in the dashboard, or start over with `bin/rails db:reset` in `cmdb/`.

## What needs more than this

The agent installer, updates, and rollbacks need systemd and a disposable machine: `agent/scripts/update-smoke.sh` and `agent/scripts/vm-test.sh` (a Debian 13 VM under QEMU). CI runs them on every agent change; they rewrite system directories, so do not run them on your own machine.
