# P1-DEPLOY: Server deployment, backups, and installation docs

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-O03: Server deployment: Docker Compose, Cloudflare tunnel, and private agent TLS

**Changed by the owner's review of #88 ([ADR 0023](../../decisions/0023-deploy-with-github-actions.md)):** the server is one container deployed by GitHub Actions onto the existing PostgreSQL container's network, and the tunnel on another VM reaches it over plain HTTP. The agent hostname's TLS is [#137](https://github.com/hostilecity/fleet-cmdb/issues/137), and backups in the deployment get their own issue; the criteria marked below moved there.

### Context

[DEC-05](../../decisions/0005-hosting-tls-deployment.md): Docker Compose; the dashboard is published through a Cloudflare tunnel (TLS at Cloudflare) with Cloudflare Access; the agent API is on a private LAN hostname with a Let's Encrypt certificate (DNS-01 through Cloudflare) and is never exposed through the tunnel.

### Scope

- Production Dockerfile (the Rails 8 default is a good start) and a compose file running Rails (Puma) with Solid Queue, PostgreSQL, a TLS proxy for the **agent hostname** that obtains its certificate by the Cloudflare DNS challenge, and the Cloudflare tunnel connector for the **dashboard hostname** only.
- Two hostnames, configured by environment: a public dashboard hostname and a private agent hostname. `config.hosts` allows exactly those two; route separation is implemented and tested in [P1-S13](p1-access.md).
- Document the tunnel configuration (it must not publish the agent hostname or any `/api/v1` path), the Cloudflare Access policy for the dashboard, and the internal DNS record that points the agent hostname at the server's LAN address.
- Rails trusts the proxies for client addresses (`assume_ssl`, trusted proxies) so per-host rate limiting and logs see the right address.
- Configuration through environment and Rails credentials, with an `.env.example` containing placeholders only. No real hostnames, addresses, tokens, or keys in the repository. The Cloudflare API token used for DNS challenges is a secret and is scoped to DNS edit for the one zone.
- Migrations on deploy (`db:prepare`), persistent volumes for PostgreSQL, certificates, and release files, and a documented upgrade procedure.
- Verify from a VM: the agent hostname serves a trusted certificate with no custom CA; the same `/api/v1` path is **not** reachable via the public dashboard hostname.

### Acceptance criteria

- [ ] A deploy by `.github/workflows/cd.yml` brings up a working dashboard with the documented configuration
- [ ] A request to `/api/v1/*` through the public dashboard hostname fails; the same request on the agent hostname succeeds (the agent hostname part: #137)
- [ ] An agent on a Debian VM verifies the agent hostname certificate with its compiled-in trust and no `ca_file` (#137, ADR 0024)
- [ ] Certificate renewal is automatic and its failure is visible (log or health) (moved to #137)
- [ ] Rebuilding the stack from backups restores state (ties into [P1-O01](p1-deploy.md); moved to [#138](https://github.com/hostilecity/fleet-cmdb/issues/138))

### As built

- `.github/workflows/cd.yml` (workflow "Deploy"): every push to `main`, and `workflow_dispatch` on `main`; `runs-on: self-hosted`, environment `production`, one deploy at a time. Over SSH (key from `SSH_PRIVATE_KEY`, host key from `DEPLOY_KNOWN_HOSTS` or `ssh-keyscan`) it deploys the run's own commit (`GITHUB_SHA`; rollback is a re-run of an earlier Deploy run, or a revert), ships `cmdb/` and `docs/api/` as a tar of the checkout (the runner needs no `git`: `actions/checkout` downloads through the API), writes the app's settings over SSH standard input into a mode-0600 env file, and on the VM checks the database network (`docker network inspect`), creates the volume `fleet-cmdb_storage` (`/rails/storage`: release files, backup status), builds `fleet-cmdb:<sha>`, replaces the `fleet-cmdb` container (`-p 80:3000`, the database network, `--restart unless-stopped`, `--env-file`, then the file is deleted), waits for `/up`, and prints the status. No secret value is on a command line.
- The PostgreSQL container, its network, the role `cmdb`, and its four databases exist on the server already (provisioned elsewhere); `PGHOST` is `FLEET_DB_HOST` (default `postgres`). `db:prepare` runs the migrations on every start.
- **Trusted proxies:** none. The tunnel connector reaches port 80 directly and passes on headers a browser sent, so `FLEET_TRUSTED_PROXIES` stays unset and `HostSeparation` drops every forwarded header; a client cannot claim the agent hostname through the tunnel. Port 80 is plain HTTP on the LAN: the guide recommends a firewall rule allowing it only from the tunnel VM.
- **No Thruster:** the image runs Puma directly on port 3000. Behind Thruster every request reaches Rails from loopback, which `HostSeparation` always trusts, so a forged `X-Forwarded-Host` would pass (confirmed against the app in production mode).
- **Release import egress:** the import uses only `github.com` and the download host it redirects to (`release-assets.githubusercontent.com`), not `api.github.com`.
- **Verification:** `.github/workflows/deploy-ci.yml` builds the image as `cd.yml` does, runs it against a throwaway `postgres:17` with the role `cmdb` owning the four databases (the same env-file mechanism and a published port), waits for `/up`, and checks that the dashboard hostname serves sign-in, refuses `/api/v1` (also with a forged `X-Forwarded-Host` or `Forwarded`) and `/health`, and that `/health` is 503 until a backup exists. It also runs shellcheck and actionlint. The tunnel, Access, and the runner need the owner's accounts and are checked by following [install-server.md](../../operations/install-server.md).

## P1-O01: Database backup and tested restore procedure

### Context

NFR-2 requires a documented, restorable backup procedure before Phase 1 is considered done. A backup that has never been restored is not a backup.

### Scope

- Scheduled logical backups (for example `pg_dump` via a systemd timer or a compose sidecar) with a retention policy and a location off the server machine.
- The release files (`FLEET_RELEASES_DIR`, [P1-RELEASES](p1-releases.md)) are in the backup or can be rebuilt: say which. Imported releases can be re-imported from GitHub, but uploaded ones cannot, and the database rows are checked against the files. The restore drill covers a release download after restore.
- Documentation of what else is needed to restore: the Rails master key (or credentials), the Cloudflare API token and tunnel credentials, the agent hostname certificate state, and the configuration environment. These must be backed up separately and never committed.
- A restore script or runbook, and a **restore drill**: restore into a scratch database, boot the app against it, and check that hosts, snapshots, and the audit log are present.
- A check that fails loudly if the latest backup is older than expected (surface it in [P1-S11](p1-operability.md) health or documentation of the alert).
- Delivered as `ops/backup/` (`backup.sh`, `restore.sh`, `restore-drill.sh`, systemd units) and [docs/operations/backup-and-restore.md](../../operations/backup-and-restore.md). The backup touches a status file that `/health` watches (`FLEET_BACKUP_STATUS_FILE`, `FLEET_BACKUP_MAX_AGE_HOURS`); the drill's checks are `bin/rails backup:verify_restore`.

### Acceptance criteria

- [ ] The restore drill is performed and the result recorded in the Phase 1 delivery note
- [ ] A restored database boots the app and shows the expected hosts and audit entries
- [ ] The procedure is in the install and operations documentation ([P1-X03](p1-deploy.md))

## P1-X03: Installation and operations documentation (server, agent, enrollment, upgrade, uninstall)

### Scope

- Server: prerequisites, deploy, first operator, TLS, configuration reference (including the release public keys and outbound access for release import: `api.github.com`, `github.com`, and the release asset download hosts GitHub redirects to, over HTTPS; none is needed for uploaded releases), upgrade, backup and restore (from [P1-O01](p1-deploy.md)), where logs are, and the health endpoint.
- Agent: the dashboard install page ([P1-D08](p1-releases.md)) as the primary path; pre-registration for unattended installs; remote updates and rollouts; manual upgrade by re-running the installer; uninstall.
- Operations: revoke and re-enroll, retire, recover from a lost credential, change thresholds, read the audit log.
- Troubleshooting: certificate trust errors, `401` responses, clock skew, host stuck offline, an expired onboarding request, a halted rollout, and a rolled-back update.
- Validate by following the documents on a clean server and clean VM using only the documents; fix gaps found.

### Acceptance criteria

- [ ] The owner (or a fresh reader) completes server setup and enrolls a VM from the documents alone
- [ ] Every command in the docs has been run at least once
- [ ] Documentation links from the root `README.md`

### As built

[docs/operations/](../../operations/README.md): `install-server.md` (the GitHub Actions deployment; the agent hostname and backups in the deployment come with #137 and the backups issue), `configuration.md` (every environment variable the server reads, checked against every `ENV` use in `cmdb/`), `install-agent.md`, `fleet-operations.md`, `troubleshooting.md`, with the existing `backup-and-restore.md` and `health-and-jobs.md`. The settings tables formerly in `cmdb/README.md` moved to `configuration.md`. Rollouts are started from the Rails console until their dashboard view ([P1-UPDATES](p1-updates.md), P1-D09) arrives; `install-agent.md` says so and should switch to the dashboard then.
