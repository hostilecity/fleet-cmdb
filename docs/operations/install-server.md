# Install the server

The server runs as one Docker container, `fleet-cmdb`, on a VM on your network. It uses a PostgreSQL container that already runs there. Operators reach the dashboard through a Cloudflare tunnel whose connector runs on another VM. The tunnel and the agents both connect to the VM's internal hostname over HTTPS, with a Cloudflare Origin CA certificate the server serves itself ([ADR 0005](../decisions/0005-hosting-tls-deployment.md), [ADR 0024](../decisions/0024-cloudflare-origin-ca-for-the-server.md), [P1-DEPLOY](../backlog/specs/p1-deploy.md)). GitHub Actions deploys it (`.github/workflows/cd.yml`):

1. a self-hosted runner on the LAN connects to the VM over SSH;
2. it ships the commit, builds the image there, and replaces the container.

You set secrets and variables in GitHub; nothing is edited on the VM.

```
 Operator's browser ──HTTPS──> Cloudflare (Access) ──tunnel──> cloudflared (tunnel VM) ──HTTPS──┐
                                                                                                ├──> VM:443 ──> fleet-cmdb:3443
 Agents on your VMs ──────────────────HTTPS, internal network only─────────────────────────────┘          │ Docker network
                                                                                                postgres (existing container)
```

Both connections go to the VM's internal hostname (`fleet-vm.example.com` below), so one certificate serves both. The tunnel passes the browser's hostname along, which is how the app tells a dashboard request from an agent's: the dashboard answers only on the dashboard hostname, and the agent API only on the internal one.

**Not here yet:**
- **Agents** trust the server's certificate only from the first agent release that includes Cloudflare's Origin CA roots ([agent/trust](../../agent/trust/README.md)). Install agents from that release on ([install-agent.md](install-agent.md)).
- **Backups** come in [#138](https://github.com/hostilecity/fleet-cmdb/issues/138). Until a backup exists, `/health` reports `503` (`"backup":"failing"`). That is expected, not a fault.

Names below are placeholders:

| Placeholder | What it is |
|---|---|
| `fleet.example.com` | The dashboard hostname, in your Cloudflare zone |
| `fleet-vm.example.com` | The VM's internal hostname, resolving to `192.0.2.10` on your network (and VPN) only. Agents, the tunnel, and the runner connect to it |
| `192.0.2.10` | The fleet-cmdb VM's address |
| `192.0.2.20` | The tunnel VM's LAN address |
| `deploy` | The user the runner logs in as on the VM |
| `postgres_default` | The PostgreSQL container's Docker network |

## 1. Check the prerequisites

| You need | Check |
|---|---|
| The VM: Linux with Docker, port 443 free | `docker version`; `ss -ltn 'sport = :443'` prints only the header |
| The internal hostname resolves to the VM from the tunnel VM and from the VMs that will run agents | `getent hosts fleet-vm.example.com` on each prints `192.0.2.10` |
| A deploy user on the VM in the `docker` group (equivalent to root on the VM) | `ssh deploy@192.0.2.10 docker ps` works without `sudo` |
| The existing PostgreSQL container on its Docker network, reachable there as `postgres` (or another name: `FLEET_DB_HOST`), with the role `cmdb` owning `cmdb_production`, `cmdb_production_cache`, `cmdb_production_queue`, and `cmdb_production_cable` | `docker network ls` shows the network; `docker run --rm --network postgres_default postgres:17 pg_isready -h postgres` prints `accepting connections` |
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
2. `database network postgres_default exists` and the build;
3. `wait for /up` (the first start migrates the databases);
4. the container's status, and `/health` (`503` until backups exist).

The deploy stops with a clear message if the network is missing, a required setting is not set, or agents would not trust the certificate; only names are printed, never values (and the certificate's names and expiry, which are not secret). The server does not start if the key does not match the certificate or the certificate does not cover `FLEET_AGENT_HOST`; `docker logs fleet-cmdb` says which. Secret values reach the VM over SSH standard input, into a mode-0600 env file for `docker run --env-file`, which is deleted once the container has started. Docker keeps them in the container's configuration (`docker inspect`), which only users in the `docker` group can read.

**Check:**
- Open `https://fleet.example.com` in a browser. Pass Access, and the sign-in page opens.
- From a VM on your network, with this repository's `agent/trust` files: `curl -s -o /dev/null -w '%{http_code}\n' --cacert <(cat agent/trust/*.pem) https://fleet-vm.example.com/up` prints `200`. That is the certificate check agents make.

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

- **Upgrade:** merge to `main`; every push to `main` deploys. Migrations run on start (`db:prepare`).
- **Change a setting:** change the secret or variable in GitHub, then run the workflow.
- **Renew the certificate:** before it expires (Settings shows when), create a new Origin certificate as in step 1, replace `FLEET_TLS_CERT` and `FLEET_TLS_KEY`, and run the workflow. Agents need nothing.
- **Roll back:** open the earlier Deploy run of the commit to go back to and choose **Re-run all jobs**; a run always deploys its own commit. GitHub re-runs only runs up to 30 days old: for an older commit, revert on `main` instead, and the push (or a manual run) deploys the revert. If the newer version migrated the database, the old code may not run on it: that needs a backup (a later issue).
- Two deploys never overlap; a second one waits.

## Security notes

- **Port 443 is the only published port**, and only the tunnel VM and the VMs that run agents need it. Docker's published ports bypass `ufw`'s usual rules, so limit it in the `DOCKER-USER` chain (after Docker's DNAT the port is the container's, 3443), for example `iptables -I DOCKER-USER -p tcp --dport 3443 ! -s 192.0.2.0/24 -j DROP`.
- **The dashboard through the internal hostname.** A client on your network can connect to `fleet-vm.example.com` while naming `fleet.example.com` as the host. It then reaches the dashboard without passing Cloudflare Access; Google sign-in and the operator allowlist still apply.
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

Then remove the tunnel's public hostname and the Access applications in Cloudflare, revoke the Origin certificate (**SSL/TLS > Origin Server**), the OAuth client in Google Cloud, and the `production` environment in GitHub. The databases stay in your PostgreSQL container.
