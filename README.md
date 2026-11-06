# fleet-cmdb

A configuration management database for homelab virtual machines: a Ruby on Rails server and dashboard (`cmdb/`) and a Rust agent on each VM (`agent/`). Built in phases: inventory and liveness, then config/CIS/package/vulnerability reporting, then allowlisted remote tasks. See `docs/requirements.md`.

Project structure:
```
  docs/
    requirements.md
    mockups/
    decisions/
    operations/     # runbooks: backup and restore
    api/            # agent API spec, JSON Schemas, example payloads (issue P0-CONTRACT)
    backlog/        # issues.yml (issue stubs) and specs/ (implementation details, source of truth)
  cmdb/
  agent/
  ops/              # backup, restore, and restore-drill scripts and systemd units
  .github/
```

- Contributing, branch and commit conventions: [CONTRIBUTING.md](CONTRIBUTING.md)
- Decisions (ADRs): [docs/decisions/](docs/decisions/README.md)
- Running it all locally (tests, server, a simulated fleet, a real agent): [docs/operations/running-locally.md](docs/operations/running-locally.md)
- Server setup and development: [cmdb/README.md](cmdb/README.md)
- Backup, restore, and the restore drill: [docs/operations/backup-and-restore.md](docs/operations/backup-and-restore.md)
- Agent build and checks: [agent/README.md](agent/README.md)
- Reporting a vulnerability: [SECURITY.md](SECURITY.md)
- License: [MIT](LICENSE)
