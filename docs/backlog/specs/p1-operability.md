# P1-OPERABILITY: Retention, health, logging, job failures, and security hardening

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-S10: Retention and pruning jobs

### Scope

- Configurable retention settings (default 90 days) for inventory snapshots, recent report ids, and host status events.
- Scheduled job that prunes beyond the retention window in batches, always keeping the most recent snapshot per host.
- Audit entries are **not** pruned by default ([DEC-07](../../decisions/0007-snapshots-and-retention.md)); if an audit retention setting is added it is a separate, off-by-default setting.
- Dry-run mode and log lines stating counts deleted.
- Designed so later phases can register their own snapshot types ([P2-S12](p2-accept.md)).

### Implementation notes

- `Retention` (`cmdb/app/services/retention.rb`) prunes `inventory_snapshots` and `host_status_events` (keeping each host's newest row) and `inventory_report_receipts`. A later phase adds its own snapshot table with `Retention.register`. `RetentionPruneJob` runs daily (`config/recurring.yml`), `dry_run: true` only counts, and each run logs the counts.
- One setting, `retention.days` (default 90, 7 to 3650), covers all three tables: `bin/rails settings:retention DAYS=90`. There is no dashboard control yet (P1-D02 owns the settings page).

### Acceptance criteria

- [x] Rows older than the window are removed and newer rows are kept
- [x] The newest snapshot of each host survives regardless of age
- [x] Audit entries are untouched by default (spec)
- [ ] Pruning a large table runs in batches without long locks (verified with the [P1-O04](p1-verify.md) simulator data). Batching is specced with a small batch size; the simulator run waits for P1-O04.

## P1-S11: Health endpoint and structured logging with request and report ids

### Scope

- `/health` returning JSON for application, database, and background job liveness (for example, the age of the last recurring job run). Unauthenticated, minimal, and revealing no version numbers or internals; HTTP status reflects health so monitoring can alert on it. Include the release store: unhealthy when the files of the newest release, or of one a running rollout targets, are missing from the release directory (an existence and size check, never a scan), since every update and install depends on them. Keep the Rails `/up` route for container health checks.
- Structured (JSON or key=value) production logs with timestamp, level, request id, host id when known, report id when present, and duration.
- The request id is returned in API responses and error envelopes so an agent log line can be correlated with a server log line.

### Implementation notes

- `/health` checks: `database`, `releases` (the newest release and a running rollout's target), `backup`, `failed_jobs`, `job_liveness`. The liveness check is "the recurring liveness evaluation finished within 5 minutes".
- Production logs are one JSON object per line (`StructuredLogFormatter`): time, level, message, and `request_id`, `host_id`, `report_id` when known, plus a `request completed` line with `duration_ms`, controller, action, method, and status (never the query string). The request id is also the `X-Request-Id` response header and the `request_id` in every error envelope, so an agent log line is matched to a server line by that id; a report is found by `report_id`.

### Acceptance criteria

- [x] `/health` returns an unhealthy status if the database is unreachable (spec with a stubbed failure)
- [x] A single heartbeat or inventory report can be traced end to end by request id or report id in server logs
- [x] Log output contains no authorization headers, tokens, or credentials (spec)

## P1-O02: Background job failure visibility and retry policy

### Scope

- Default retry policy with backoff for recurring and enqueued jobs; no job fails silently.
- Persistent failures are visible to an operator: a dashboard banner or indicator with a count of failed jobs, linking to a failed-jobs view (Mission Control Jobs mounted behind operator authentication is the likely fit; confirm against the [DEC-02](../../decisions/0002-server-stack.md) ADR).
- `/health` ([P1-S11](p1-operability.md)) reports unhealthy when jobs are failing or the recurring liveness job has not run recently.
- Stale-data cleanup jobs from [P1-S10](p1-operability.md) are covered.

### Implementation notes

- Mission Control Jobs was not added: the failed-jobs page is a small read-only view of Solid Queue's own failed executions (`FailedJobsController`, `JobHealth`), behind the same operator sign-in as every dashboard page, so there is no second engine and no second authentication path to harden. Retrying or discarding a failed job is not offered yet; failures older than 24 hours stay listed but no longer count toward the banner or `/health`.
- `ApplicationJob` retries any error 5 times with polynomial backoff (about 3 s, 18 s, 83 s, 4 min); then Solid Queue keeps the execution as failed.

### Acceptance criteria

- [x] A job forced to fail retries with backoff, then appears in the operator-visible failed list
- [x] The banner or indicator shows a nonzero failed count and links to details
- [x] The failed-jobs view requires operator sign-in

## P1-S12: Server security hardening: output escaping, CSP, parameter filtering

### Context

A compromised VM must not be able to inject markup into an operator's browser through any field the agent reports.

### Scope

- Regression specs that store hostile values (script tags, attribute-breaking quotes, control characters, very long strings, bidirectional text) in every agent-supplied and operator-supplied field (hostname, OS, CPU model, addresses, mount names, collection warnings, notes, tags), then render every dashboard view and assert the output is escaped.
- Content Security Policy that forbids inline script and third-party origins; verify Turbo and Stimulus still work.
- `filter_parameters` covering `authorization`, `token`, `secret`, `credential`, `password`, and similar; verified against real log output.
- `config.hosts` allowlist, CSRF protection confirmed on all dashboard forms, secure cookie flags verified in a request spec.
- Brakeman and bundler-audit clean in CI with any ignores justified in writing.

### Implementation notes

- The Content Security Policy (`config/initializers/content_security_policy.rb`) allows only this site and a per-request nonce for scripts and styles, nothing from other origins, and Google as a form target for sign-in. `spec/requests/hostile_input_spec.rb` stores six kinds of hostile string in every field the dashboard shows and renders every dashboard view; it fails if a new GET view is not listed.
- Also verified in specs: CSRF tokens in every form and a 422 for every state-changing dashboard route without one, session cookie flags, and an unknown Host answered with an empty 404. Brakeman and bundler-audit stay clean with no ignores added.

### Acceptance criteria

- [x] The hostile-input specs pass for every view that shows agent-supplied text
- [x] CSP header present on dashboard responses and blocks inline script in a browser check (header and nonce rules in a spec; the blocking was checked by hand in Chromium for the delivering pull request)
- [x] No secret-like parameter appears unfiltered in logs
