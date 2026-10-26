# P2-CONFIG-REPORTS: Config fact manifest, config reports, and report requests

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-S01: Config fact manifest and fact schema

### Scope

- A versioned fact manifest stored as data in the server (for example `cmdb/config/fact_manifest.yml`) and published at `GET /api/v1/manifest/config` (authenticated as a host). Each fact has a key, a type, a description, and the manifest version that introduced it.
- Types: string, integer, boolean, list of strings, file attributes (mode, owner, group), and service state. The type set is the contract for both the report validator ([P2-S02](p2-config-reports.md)) and the rule evaluator ([P2-S05](p2-cis-engine.md)).
- Initial facts cover SSH server settings, password and login policy values, firewall enabled state, automatic updates enabled state, permissions on a defined list of sensitive files, running and enabled services, and local user accounts with login shells (FR-2.1). The file list is part of the manifest, not hard-coded in the agent.
- Schema and examples added to `docs/api/` ([SETUP-06](p0-contract.md)).
- Adding a fact is a manifest change plus agent support; old agents simply report new facts as unsupported.

### Acceptance criteria

- [ ] The manifest validates against its schema and every fact has an example value
- [ ] An unknown manifest version or key in a report is handled per [DEC-08](../../decisions/0008-api-conventions.md)
- [ ] Documented procedure for adding a fact

## P2-S02: Config report endpoint, snapshots, and diff

### Scope

- `POST /api/v1/reports/config`: report id, schema version, manifest version, collection time, and a map of fact key to `{state, value, reason}` where state is `ok`, `unreadable`, or `unsupported`.
- Validation against the manifest (type, length, allowed values); unreadable and unsupported facts must carry a reason. Facts never silently omitted: facts present in the manifest but absent from the report are recorded as `missing`.
- Snapshot created only when the facts change (content hash), reports deduplicated by report id, as in [P1-S08](p1-inventory.md). Current facts stored per host.
- Diff service comparing two snapshots of one host: added, removed, and changed facts, including state changes (ok to unreadable).
- Triggers evaluation ([P2-S06](p2-cis-engine.md)) after a new snapshot is stored, through a background job.

### Acceptance criteria

- [ ] AC-2.1 (server half): a changed fact appears in the diff between two snapshots
- [ ] AC-2.5 (server half): unreadable facts are stored and shown with their reason
- [ ] Duplicate report ids and unchanged content create no new snapshot
- [ ] Invalid values are rejected with no partial write

## P2-S03: Report-requested flag and heartbeat directive

### Scope

- Record a report request for a host (types: config, packages, inventory), with the requesting operator and time; audit the request ([P1-S03](p1-hosts.md)).
- Include outstanding requests in the heartbeat response `directives` ([DEC-08](../../decisions/0008-api-conventions.md)); the contract example is updated in [P2-X01](p2-accept.md).
- Clear a request when a report of that type collected after the request arrives; expire requests that are never satisfied (for example after an hour) and show that.
- Rate limit per host.
- Endpoint or action used by the dashboard button ([P2-D02](p2-dash-host.md)).

### Acceptance criteria

- [ ] An operator request appears as a directive on the next heartbeat and not afterwards once satisfied
- [ ] Rapid repeat requests are rate limited
- [ ] An old agent that ignores directives is unaffected
