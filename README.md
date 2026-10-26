# fleet-cmdb

A configuration management database for homelab virtual machines: a Ruby on Rails server and dashboard (`cmdb/`) and a Rust agent on each VM (`agent/`). Built in phases: inventory and liveness, then config/CIS/package/vulnerability reporting, then allowlisted remote tasks. See `docs/requirements.md`.

Project structure:
```
  docs/
    requirements.md
    mockups/
    decisions/
    api/            # agent API spec, JSON Schemas, example payloads (issue P0-CONTRACT)
    backlog/        # issues.yml (issue stubs) and specs/ (implementation details, source of truth)
  cmdb/
  agent/
  .github/
```

- Contributing, branch and commit conventions: [CONTRIBUTING.md](CONTRIBUTING.md)
- Decisions (ADRs): [docs/decisions/](docs/decisions/README.md)
- Server setup and development: [cmdb/README.md](cmdb/README.md)
- Agent build and checks: [agent/README.md](agent/README.md)
- Reporting a vulnerability: [SECURITY.md](SECURITY.md)
- License: [MIT](LICENSE)
