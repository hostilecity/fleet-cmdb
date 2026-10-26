# P0-CONTRACT: API contract workspace (docs/api)

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Context

NFR-5 requires that a payload accepted in Phase 1 stays readable in later phases. That is only enforceable if the server and the agent test against the same artefacts rather than each side's idea of the format.

## Scope

- `docs/api/README.md`: the conventions from [DEC-08](../../decisions/0008-api-conventions.md).
- `docs/api/schemas/`: one JSON Schema per request and response, versioned by `schema_version`.
- `docs/api/examples/`: valid and invalid example payloads per endpoint (use obviously fake values).
- Server test helper that loads every example and validates it against the schema, and runs the valid examples through the real endpoint ([P1-X01](p1-accept.md) extends this).
- Agent test helper that serialises its report structs and validates them against the same schemas.
- A short guide: how to change a schema (bump version, keep old examples, add a migration note).

## Acceptance criteria

- [ ] Adding a field to a schema without a matching example fails a test
- [ ] Both `cmdb/` and `agent/` test suites read from `docs/api/` rather than keeping their own copies
- [ ] Examples contain no real hostnames, addresses, or credentials
