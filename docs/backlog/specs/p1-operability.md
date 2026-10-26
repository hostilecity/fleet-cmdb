# P1-OPERABILITY: Retention, health, logging, job failures, and security hardening

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-S10: Retention and pruning jobs

### Scope

- Configurable retention settings (default 90 days) for inventory snapshots, recent report ids, and host status events.
- Scheduled job that prunes beyond the retention window in batches, always keeping the most recent snapshot per host.
- Audit entries are **not** pruned by default ([DEC-07](../../decisions/0007-snapshots-and-retention.md)); if an audit retention setting is added it is a separate, off-by-default setting.
- Dry-run mode and log lines stating counts deleted.
- Designed so later phases can register their own snapshot types ([P2-S12](p2-accept.md)).

### Acceptance criteria

- [ ] Rows older than the window are removed and newer rows are kept
- [ ] The newest snapshot of each host survives regardless of age
- [ ] Audit entries are untouched by default (spec)
- [ ] Pruning a large table runs in batches without long locks (verified with the [P1-O04](p1-verify.md) simulator data)

## P1-S11: Health endpoint and structured logging with request and report ids

### Scope

- `/health` returning JSON for application, database, and background job liveness (for example, the age of the last recurring job run). Unauthenticated, minimal, and revealing no version numbers or internals; HTTP status reflects health so monitoring can alert on it. Keep the Rails `/up` route for container health checks.
- Structured (JSON or key=value) production logs with timestamp, level, request id, host id when known, report id when present, and duration.
- The request id is returned in API responses and error envelopes so an agent log line can be correlated with a server log line.

### Acceptance criteria

- [ ] `/health` returns an unhealthy status if the database is unreachable (spec with a stubbed failure)
- [ ] A single heartbeat or inventory report can be traced end to end by request id or report id in server logs
- [ ] Log output contains no authorization headers, tokens, or credentials (spec)

## P1-O02: Background job failure visibility and retry policy

### Scope

- Default retry policy with backoff for recurring and enqueued jobs; no job fails silently.
- Persistent failures are visible to an operator: a dashboard banner or indicator with a count of failed jobs, linking to a failed-jobs view (Mission Control Jobs mounted behind operator authentication is the likely fit; confirm against the [DEC-02](../../decisions/0002-server-stack.md) ADR).
- `/health` ([P1-S11](p1-operability.md)) reports unhealthy when jobs are failing or the recurring liveness job has not run recently.
- Stale-data cleanup jobs from [P1-S10](p1-operability.md) are covered.

### Acceptance criteria

- [ ] A job forced to fail retries with backoff, then appears in the operator-visible failed list
- [ ] The banner or indicator shows a nonzero failed count and links to details
- [ ] The failed-jobs view requires operator sign-in

## P1-S12: Server security hardening: output escaping, CSP, parameter filtering

### Context

A compromised VM must not be able to inject markup into an operator's browser through any field the agent reports.

### Scope

- Regression specs that store hostile values (script tags, attribute-breaking quotes, control characters, very long strings, bidirectional text) in every agent-supplied and operator-supplied field (hostname, OS, CPU model, addresses, mount names, collection warnings, notes, tags), then render every dashboard view and assert the output is escaped.
- Content Security Policy that forbids inline script and third-party origins; verify Turbo and Stimulus still work.
- `filter_parameters` covering `authorization`, `token`, `secret`, `credential`, `password`, and similar; verified against real log output.
- `config.hosts` allowlist, CSRF protection confirmed on all dashboard forms, secure cookie flags verified in a request spec.
- Brakeman and bundler-audit clean in CI with any ignores justified in writing.

### Acceptance criteria

- [ ] The hostile-input specs pass for every view that shows agent-supplied text
- [ ] CSP header present on dashboard responses and blocks inline script in a browser check
- [ ] No secret-like parameter appears unfiltered in logs
