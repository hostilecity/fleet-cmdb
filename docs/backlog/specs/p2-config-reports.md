# P2-CONFIG-REPORTS: Config fact manifest, config reports, and report requests

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-S01: Config fact manifest and fact schema

### Scope

- A versioned fact manifest stored as data in the server (for example `cmdb/config/fact_manifest.yml`) and published at `GET /api/v1/manifest/config` (authenticated as a host). Each fact has a key, a type, a description, and the manifest version that introduced it.
- Types: string, integer, boolean, list of strings, file attributes (mode, owner, group), and service state. The type set is the contract for both the report validator ([P2-S02](p2-config-reports.md)) and the rule evaluator ([P2-S05](p2-cis-engine.md)).
- Initial facts cover SSH server settings, password and login policy values, firewall enabled state, automatic updates enabled state, permissions on a defined list of sensitive files, running and enabled services, and local user accounts with login shells (FR-2.1). The file list is part of the manifest, not hard-coded in the agent.
- Schema and examples added to `docs/api/` ([SETUP-06](p0-contract.md)).
- Adding a fact is a manifest change plus agent support; old agents simply report new facts as unsupported.
- Delivered as `cmdb/config/fact_manifest.yml` (89 facts: 43 settings, 22 files, 24 services) loaded by `ConfigManifest` (`cmdb/lib/config_manifest.rb`), published at `GET /api/v1/manifest/config` (`config-manifest.response` in `docs/api/`), with the procedure in [docs/operations/config-facts.md](../../operations/config-facts.md). Facts are never removed, retyped, or tightened: `spec/fixtures/config_manifest/frozen_facts.yml` and its specs enforce it. File attributes and service states are `null` when the file or unit does not exist. The handling of an unknown manifest version or key in a report is part of P2-S02.

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
- Delivered as `POST /api/v1/reports/config` (`config.request` and `config.response` in `docs/api/`, gzip allowed, 4 MiB of JSON) with `AgentApi::ConfigReport` (`cmdb/lib/agent_api/config_report.rb`) checking values against the manifest, `ConfigRecorder` storing `host_configs` (current facts per host), `config_snapshots`, and `config_report_receipts` under the host row lock, and `ConfigDiff`. Snapshots and receipts are pruned by `Retention`, the newest snapshot per host kept. Handling of unknown input (the P2-S01 criterion, per DEC-08): a fact key the manifest does not have is ignored, logged, and kept in `ignored_keys`; an unknown field in a fact is ignored and logged; a manifest version newer than the server's is refused with `validation_failed`, and an older one is accepted, the facts added since recorded as missing with a reason naming the version that added them. A NUL in a value is refused, as PostgreSQL cannot store it. The response carries the server's manifest version so an agent knows to fetch it again. A new snapshot enqueues rule evaluation for the host (`CisEvaluationJob`, added with P2-S06). Showing unreadable facts (AC-2.5) is server-side storage here (`HostConfig#unreadable`); the page is P2-D02.

### Acceptance criteria

- [ ] AC-2.1 (server half): a changed fact appears in the diff between two snapshots
- [ ] AC-2.5 (server half): unreadable facts are stored and shown with their reason
- [ ] Duplicate report ids and unchanged content create no new snapshot
- [ ] Invalid values are rejected with no partial write

## P2-S03: Report-requested flag and heartbeat directive

### Scope

- Record a report request for a host (types: config, packages, inventory), with the requesting operator and time; audit the request ([P1-S03](p1-hosts.md)).
- Include outstanding requests in the heartbeat response `directives` as one named directive, for example `report_request` with the requested types ([DEC-20](../../decisions/0020-named-heartbeat-directives.md)); the schema and examples are added in [P2-X01](p2-accept.md). Adding it is an additive v1 change.
- Clear a request when a report of that type collected after the request arrives; expire requests that are never satisfied (for example after an hour) and show that.
- Rate limit per host.
- Endpoint or action used by the dashboard button ([P2-D02](p2-dash-host.md)).
- Delivered as `report_requests` (one row per host and report type, `pending`, `satisfied` with the report id, or `expired` with `expired_at`; one pending per host and type by a partial unique index) changed only by `ReportRequests` (`cmdb/app/services/report_requests.rb`). The action is `POST /hosts/:id/request_reports` (`HostActionsController#request_reports`), a CSRF-protected form on the host page with the three types checked and the recent requests listed; P2-D02 moves it to the configuration tab. A request is audited as `host.report_requested` with the operator and the types. Rate limit: one request per host and type every 5 minutes, whatever happened to the previous one; a type still pending from an older request is left as it is. The heartbeat sends `"report_request": {"types": [...]}` while any request is outstanding, on every heartbeat (a lost response loses nothing), and records the first `sent_at`. Every new report (not a duplicate), changed or not, satisfies the pending request of its type when it was collected after the request: the agent's `collected_at` is moved onto the server clock by the offset its last heartbeat measured (`agent_reported_at` minus `last_seen_at`), so an agent clock behind the server's cannot keep a request open and one ahead cannot let an older report clear it; received time alone is not used, as a retried report collected before the request is not fresh. Requests stop being sent an hour after they were made and `ReportRequestExpiryJob` marks them expired every minute; Retention prunes them by `requested_at`. The `report_request` schema and examples (`docs/api/examples/v1/heartbeat.response/*/report-request*.json`) were added here rather than in P2-X01, and the agent's tests check that the current agent ignores the directive; acting on it is the agent's (#26, #27).

### Acceptance criteria

- [ ] An operator request appears as a directive on the next heartbeat and not afterwards once satisfied
- [ ] Rapid repeat requests are rate limited
- [ ] An old agent that ignores directives is unaffected
