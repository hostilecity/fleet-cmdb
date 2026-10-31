# ADR 0020: Heartbeat directives are named entries in an object

- Status: Accepted (owner, before P1-UPDATES and the first agent release)
- Decision issue: DEC-20
- Requirements: `FR-1.2`, `FR-S.5`, `NFR-5`
- Amends: [ADR 0008](0008-api-conventions.md), only the shape of `directives` in the heartbeat response (`directives: []`). Every other convention in ADR 0008 stands.

## Context

The repository described `directives` in two incompatible ways:

- ADR 0008 and the v1 contract: an array, always `[]` in Phase 1, with report requests (Phase 2) and task hints (Phase 3) planned as entries.
- [P1-AGENT-REPORT](../backlog/specs/p1-agent-report.md), [P1-UPDATES](../backlog/specs/p1-updates.md), ADR 0018, and ADR 0019: named entries, `directives.intervals` and `directives.agent_update`.

The agent on `main` accepted both. Released agents outlive server releases (ADR 0019), and the update directive is part of the contract every released agent must keep understanding (NFR-5). The shape has to be settled before P1-UPDATES (#59) adds the first real directives and before the first agent release.

## Decision

`directives` is a JSON object keyed by directive name. Each directive's value is a JSON object (or `null`), so a directive can gain optional fields later the same way the envelope does.

```json
{
  "server_time": "2026-01-01T12:00:00Z",
  "directives": {
    "intervals": {"heartbeat_seconds": 120, "inventory_seconds": 1800}
  }
}
```

**Compatibility rules.** These are part of the agent protocol and hold for every schema version:

1. **Every directive is optional.** A response with no directives sends `"directives": {}`.
2. **An absent directive means no instruction.** The agent does what it would do without the server, for example it returns to its configured interval when `intervals` is absent.
3. **`null` equals absent**, for a directive and for a field inside one.
4. **Unknown names are ignored.** An agent ignores, and logs once, any directive name or directive field it does not know, so a server can add a directive without breaking older agents. Adding a directive, or an optional field to one, is an additive contract change and needs no new schema version.
5. **Changing what an existing directive or field means is breaking** and needs a new schema version (or a new directive name), as `docs/api/README.md` describes. This includes the update directive (NFR-5).
6. **Malformed is never fatal.** A directive of the wrong type, or a `directives` that is not an object, is ignored and logged once; the heartbeat still counts as accepted (ADR 0019). The server sends `directives` on every response; an agent treats a missing or `null` `directives` as `{}`.

**Directives known so far.** Each spec that adds one defines its fields in `docs/api/` with examples.

| Name | Phase | Purpose | Defined by |
|---|---|---|---|
| `intervals` | 1 | `heartbeat_seconds` and `inventory_seconds` the server wants, each optional, clamped by the agent to its config bounds (ADR 0019) | v1 contract (this ADR), sent by [P1-UPDATES](../backlog/specs/p1-updates.md) |
| `agent_update` | 1 | The release to install (ADR 0018) | [P1-UPDATES](../backlog/specs/p1-updates.md) |
| report requests | 2 | Outstanding on-demand report requests ([ADR 0013](0013-on-demand-reports.md)), for example `"report_request": {"types": ["config"]}` | [P2-CONFIG-REPORTS](../backlog/specs/p2-config-reports.md) (P2-S03) |
| task hint | 3 | "Tasks are waiting", so the agent polls promptly, for example `"tasks": {"available": true}` | [P3-TASK-API](../backlog/specs/p3-task-api.md) |

The Phase 2 and 3 names and fields above are illustrations; their specs choose the final ones. Each is one named directive, not a list of typed entries: several report types fit in one `report_request` object, and an agent that predates it ignores the name.

**Rejected:** an array of typed entries (`[{"type": "intervals", ...}]`), as ADR 0008 planned.

- Two entries of the same type are possible and need a rule (first wins, last wins, merge, or reject) that every agent must implement identically, forever.
- Each entry needs a `type` discriminator, and validating it means a `oneOf` per type in the schema; the object form gives each directive its own property, schema, and examples.
- An agent has to scan the list to find a directive instead of looking it up by name, and "absent means no instruction" is less obvious.
- It buys nothing the object lacks: the order of directives carries no meaning, and repeated requests (several report types) fit inside one named directive.

## Consequences

- The v1 contract changes in place (`heartbeat.response`: `directives` is an object, with `intervals` defined and `agent_update` loosely typed until P1-UPDATES defines its fields). v1 has no released agents, so this follows the pre-release rule in the `docs/api/README.md` change log and needs no version bump.
- The server sends `"directives": {}` until P1-UPDATES sends `intervals` and `agent_update`.
- The agent accepts only the object (or `null`). An array is logged once as a problem and ignored; it never fails a heartbeat.
- Phase 2 and Phase 3 directives are additive v1 changes, and the Phase 1 agent ignores them ([P2-X01](../backlog/specs/p2-accept.md)).
