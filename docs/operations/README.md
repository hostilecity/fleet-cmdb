# Installation and operations

For whoever installs and runs a fleet-cmdb server. Read them in this order the first time.

| Guide | What it covers |
|---|---|
| [install-server.md](install-server.md) | Prerequisites, Cloudflare tunnel and Access, the agent hostname and its certificate, Google sign-in, deploying with Docker Compose (all-in-one, or with an existing PostgreSQL and a tunnel on another machine, deployed by GitHub Actions), the first operator, logs, certificate renewal, upgrading and rolling back, uninstalling |
| [configuration.md](configuration.md) | Every server setting, its default, and the outbound access the server needs |
| [backup-and-restore.md](backup-and-restore.md) | What is backed up, scheduling, restore, and the restore drill |
| [install-agent.md](install-agent.md) | Installing the agent with approval or a one-time token, remote and manual updates, rollback, uninstall |
| [fleet-operations.md](fleet-operations.md) | Revoke, re-enroll, retire, lost credentials, liveness thresholds, operators, the audit log |
| [health-and-jobs.md](health-and-jobs.md) | `/health`, failed jobs, the server log format, data retention |
| [cis-rules.md](cis-rules.md) | The starter CIS-aligned rules, adding and tuning a rule, and the licensing rules for rule text |
| [config-facts.md](config-facts.md) | The configuration fact manifest and how to add a fact |
| [agent-config-facts.md](agent-config-facts.md) | What the agent reads for each configuration fact, and how to check a report |
| [agent-packages.md](agent-packages.md) | Where the agent's package list comes from, `skipped`, `unsupported`, `unreadable`, and checking it against a host (AC-2.3) |
| [troubleshooting.md](troubleshooting.md) | Certificate errors, `401`, clock skew, offline hosts, expired onboarding, halted rollouts, rolled-back updates |

For development and testing: [running-locally.md](running-locally.md), [fleet-simulator.md](fleet-simulator.md), and [agent-soak.md](agent-soak.md).

Agent internals (options, files, exit codes, the update mechanism): [agent/README.md](../../agent/README.md). Releases and the release keys: [docs/releases.md](../releases.md).
