# Install the server

The server runs as one Docker container, `fleet-cmdb`, on a VM on your LAN. It uses a PostgreSQL container that already runs there, and is published to operators through a Cloudflare tunnel whose connector runs on another VM ([ADR 0005](../decisions/0005-hosting-tls-deployment.md), [P1-DEPLOY](../backlog/specs/p1-deploy.md)). GitHub Actions deploys it (`.github/workflows/cd.yml`):

1. a self-hosted runner on the LAN connects to the VM over SSH;
2. it ships the commit, builds the image there, and replaces the container.

You set secrets and variables in GitHub; nothing is edited on the VM.

```
 Operator's browser ──HTTPS──> Cloudflare (Access) ──tunnel──> cloudflared (tunnel VM) ──HTTP──> VM:80 ──> fleet-cmdb:3000
                                                                                                             │ Docker network
                                                                                                   postgres (existing container)
```

**Not here yet:**
- **The agent hostname and its TLS proxy** come in [#137](https://github.com/hostilecity/fleet-cmdb/issues/137). Until then no agent can be installed; [install-agent.md](install-agent.md) applies after it.
- **Backups** come in [#138](https://github.com/hostilecity/fleet-cmdb/issues/138). Until a backup exists, `/health` reports `503` (`"backup":"failing"`). That is expected, not a fault.

Names below are placeholders:

| Placeholder | What it is |
|---|---|
| `fleet.example.com` | The dashboard hostname, in your Cloudflare zone |
| `agent.fleet.example.com` | The agent hostname (used from [#137](https://github.com/hostilecity/fleet-cmdb/issues/137)) |
| `192.0.2.10` | The fleet-cmdb VM's LAN address |
| `192.0.2.20` | The tunnel VM's LAN address |
| `deploy` | The user the runner logs in as on the VM |
| `postgres_default` | The PostgreSQL container's Docker network |

## 1. Check the prerequisites

| You need | Check |
|---|---|
| The VM: Linux with Docker, port 80 free | `docker version`; `ss -ltn 'sport = :80'` prints only the header |
| A deploy user on the VM in the `docker` group (equivalent to root on the VM) | `ssh deploy@192.0.2.10 docker ps` works without `sudo` |
| The existing PostgreSQL container on its Docker network, reachable there as `postgres` (or another name: `FLEET_DB_HOST`), with the role `cmdb` owning `cmdb_production`, `cmdb_production_cache`, `cmdb_production_queue`, and `cmdb_production_cable` | `docker network ls` shows the network; `docker run --rm --network postgres_default postgres:17 pg_isready -h postgres` prints `accepting connections` |
| A self-hosted GitHub Actions runner on the LAN, registered for this repository, with `bash`, `git`, and `ssh`, that can reach the VM on port 22 | **Settings > Actions > Runners** shows it **Idle** |
| A Cloudflare tunnel with its connector on the tunnel VM, and Cloudflare Access | The tunnel shows **Healthy** in Zero Trust |
| A Google Cloud project, for the operators' sign-in | |

**SSH access for the runner.** On your workstation:

```sh
ssh-keygen -t ed25519 -N '' -C fleet-cmdb-deploy -f fleet-cmdb-deploy
ssh-copy-id -i fleet-cmdb-deploy.pub deploy@192.0.2.10
ssh-keyscan -H 192.0.2.10 2>/dev/null     # host keys for DEPLOY_KNOWN_HOSTS: compare with the VM's own first
```

The private key goes into the secret `SSH_PRIVATE_KEY`; then delete both files.

**Google OAuth client.**
1. In the Google Cloud console, open **APIs & Services > Credentials** and create an **OAuth client ID** of type **Web application**.
2. Set the authorised redirect URI to `https://fleet.example.com/auth/google_oauth2/callback`.
3. On the consent screen, use **Internal** (Workspace) or **External** with your operators as test users. The scopes are `openid`, `email`, and `profile`.

## 2. Create the GitHub environment

In **Settings > Environments**, create **`production`**. Under **Deployment branches and tags**, allow only `main`. Add a required reviewer if every deploy should wait for your approval. Then add:

| Name | Kind | Example | What it is |
|---|---|---|---|
| `SSH_PRIVATE_KEY` | Secret | the `fleet-cmdb-deploy` file | The key the runner logs in to the VM with |
| `SECRET_KEY_BASE` | Secret | output of `openssl rand -hex 64` | Signs and encrypts session cookies; changing it signs everyone out |
| `DATABASE_PASSWORD` | Secret | | Password of the PostgreSQL role `cmdb` |
| `GOOGLE_CLIENT_ID` | Secret | `123456789012-abc.apps.googleusercontent.com` | The OAuth client (step 1) |
| `GOOGLE_CLIENT_SECRET` | Secret | `GOCSPX-…` | Its secret |
| `FLEET_ADVISORY_FEED_TOKEN` | Secret, optional | | Only for an advisory mirror that needs a bearer token |
| `DEPLOY_HOST` | Variable | `192.0.2.10` | The VM, as the runner reaches it |
| `DEPLOY_USER` | Variable | `deploy` | The deploy user |
| `DEPLOY_DIR` | Variable, optional | `fleet-cmdb` (the default) | Working directory on the VM, relative to the deploy user's home; the code and env file are removed after each deploy |
| `DEPLOY_KNOWN_HOSTS` | Variable, recommended | the checked `ssh-keyscan -H` lines | The VM's SSH host keys. Unset: each deploy trusts the key the VM presents |
| `FLEET_DB_NETWORK` | Variable | `postgres_default` | The PostgreSQL container's Docker network |
| `FLEET_DB_HOST` | Variable, optional | `postgres` (the default) | The PostgreSQL container's name on it |
| `FLEET_DASHBOARD_HOST` | Variable | `fleet.example.com` | The dashboard hostname |
| `FLEET_AGENT_HOST` | Variable | `agent.fleet.example.com` | Required at boot; served from [#137](https://github.com/hostilecity/fleet-cmdb/issues/137) |
| `FLEET_RELEASE_KEY_CURRENT` | Variable, optional for now | `RWQ…` | Second line of `agent/release-keys/current.pub` ([docs/releases.md](../releases.md)); needed to import agent releases |
| `FLEET_RELEASE_KEY_NEXT` | Variable, optional | `RWQ…` | Second line of `next.pub` |
| `RAILS_LOG_LEVEL` | Variable, optional | `info` (the default) | |
| `FLEET_EXTRA_SETTINGS` | Variable, optional | `FLEET_SESSION_IDLE_MINUTES=60` | Any other non-secret setting of [configuration.md](configuration.md), one `NAME=value` per line |
| `DEPLOY_ON_PUSH` | **Repository** variable | `true` | Deploy every push to `main`. Unset: deploys start only by hand |

`DEPLOY_ON_PUSH` is a repository variable (**Settings > Secrets and variables > Actions > Variables**), because the workflow decides whether to run before it enters the environment.

## 3. Publish the dashboard through the tunnel

In **Cloudflare Zero Trust > Networks > Tunnels**, open the tunnel whose connector runs on the tunnel VM and add a public hostname:
- subdomain `fleet`, domain `example.com`, path empty;
- service **HTTP**, URL **`192.0.2.10:80`**.

**Never add the agent hostname or an `/api` path to the tunnel.** The app refuses `/api/v1` on the dashboard hostname anyway (`cmdb/lib/middleware/host_separation.rb`).

In **Zero Trust > Access > Applications**, add a **Self-hosted** application for `fleet.example.com`, with an **Allow** policy for your operators' email addresses. Operators then pass Access and also sign in with Google as an allowlisted operator (step 5).

## 4. Deploy

Open **Actions > Deploy > Run workflow**, pick branch `main`, and leave **ref** empty. The first run takes a few minutes, because the image builds on the VM. The log shows:
1. the commit;
2. `database network postgres_default exists` and the build;
3. `wait for /up` (the first start migrates the databases);
4. the container's status, and `/health` (`503` until backups exist).

The deploy stops with a clear message if the network is missing or a required setting is not set; only names are printed, never values. Secret values reach the VM over SSH standard input, into a mode-0600 env file for `docker run --env-file`, which is deleted once the container has started. Docker keeps them in the container's configuration (`docker inspect`), which only users in the `docker` group can read.

**Check:** open `https://fleet.example.com` in a browser. Pass Access, and the sign-in page opens.

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
docker exec fleet-cmdb curl -s http://localhost:3000/health
```

Release files and the backup status file are in the Docker volume `fleet-cmdb_storage`, which survives every deploy. The database is in your PostgreSQL container.

## 7. Upgrade, change a setting, roll back

- **Upgrade:** merge to `main`. With `DEPLOY_ON_PUSH=true` the push deploys; otherwise run the workflow. Migrations run on start (`db:prepare`).
- **Change a setting:** change the secret or variable in GitHub, then run the workflow.
- **Roll back:** run the workflow with **ref** set to an earlier commit of `main` (`git log --oneline origin/main`), or **Re-run all jobs** on that commit's earlier Deploy run. If the newer version migrated the database, the old code may not run on it: that needs a backup (a later issue).
- Two deploys never overlap; a second one waits.

## Security notes

- **Port 80 is plain HTTP on the LAN.** Anyone on the LAN can reach the dashboard there without Cloudflare Access; Google sign-in and the operator allowlist still apply. Until [#137](https://github.com/hostilecity/fleet-cmdb/issues/137), the same port also answers the agent hostname to a client that sends that `Host` header. Allow port 80 only from the tunnel VM with a host firewall rule. Docker's published ports bypass `ufw`'s usual rules, so put it in the `DOCKER-USER` chain, for example `iptables -I DOCKER-USER -p tcp --dport 3000 ! -s 192.0.2.20 -j DROP` (after Docker's DNAT the port is the container's, 3000).
- **This repository is public, and the runner is self-hosted.** A pull request from a fork runs its own workflows and could ask for `runs-on: self-hosted`, which would run code on your LAN.
  - In **Settings > Actions > General**, require approval for fork pull request workflows from **all outside collaborators**.
  - If the repository belongs to an organisation, put the runner in a runner group limited to this repository and to `.github/workflows/cd.yml` on `main`.
  - The production secrets are out of a fork's reach, because only `main` may use the environment.

## Uninstall

```sh
docker rm -f fleet-cmdb
docker volume rm fleet-cmdb_storage       # deletes uploaded release files
docker image rm $(docker images -q fleet-cmdb)
```

Then remove the tunnel's public hostname and the Access application in Cloudflare, the OAuth client in Google Cloud, and the `production` environment in GitHub. The databases stay in your PostgreSQL container.
