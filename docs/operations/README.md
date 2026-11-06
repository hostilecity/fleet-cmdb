# Installation and operations

For whoever installs and runs a fleet-cmdb server. Read them in this order the first time.

| Guide | What it covers |
|---|---|
| [install-server.md](install-server.md) | Prerequisites, Cloudflare tunnel and Access, the agent hostname and its certificate, Google sign-in, deploying with Docker Compose, the first operator, logs, certificate renewal, upgrading, uninstalling |
| [configuration.md](configuration.md) | Every server setting, its default, and the outbound access the server needs |
| [backup-and-restore.md](backup-and-restore.md) | What is backed up, scheduling, restore, and the restore drill |
| [install-agent.md](install-agent.md) | Installing the agent with approval or a one-time token, remote and manual updates, rollback, uninstall |
| [fleet-operations.md](fleet-operations.md) | Revoke, re-enroll, retire, lost credentials, liveness thresholds, operators, the audit log |
| [health-and-jobs.md](health-and-jobs.md) | `/health`, failed jobs, the server log format, data retention |
| [troubleshooting.md](troubleshooting.md) | Certificate errors, `401`, clock skew, offline hosts, expired onboarding, halted rollouts, rolled-back updates |

Agent internals (options, files, exit codes, the update mechanism): [agent/README.md](../../agent/README.md). Releases and the release keys: [docs/releases.md](../releases.md).
