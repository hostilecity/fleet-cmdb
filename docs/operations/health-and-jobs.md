# Health, logs, failed jobs, and retention

For the server owner. Hostnames below are examples (`vm-01.example.lan`, `agent.fleet.example.lan`).

## `GET /health`

Served on the agent hostname and on localhost, never the dashboard hostname. No sign-in. It answers `200 {"status":"ok"}` or `503 {"status":"unhealthy"}` with each check as `ok` or `failing` and nothing else (no versions, counts, or error text; the server log has the detail). Point the uptime monitor at it. `/up` stays the container's liveness check.

| Check | Fails when |
|---|---|
| `database` | a query does not succeed |
| `releases` | the binary of the newest release, or of a running rollout's target, is missing or has the wrong size |
| `backup` | the last complete backup is missing or older than `FLEET_BACKUP_MAX_AGE_HOURS` ([backup-and-restore.md](backup-and-restore.md)) |
| `failed_jobs` | a background job failed all its retries in the last 24 hours |
| `job_liveness` | the recurring liveness evaluation has not succeeded in the last 5 minutes: the scheduler, a worker, or the queue database is down, or the evaluation keeps raising (an attempt that raised and was retried does not count) |

## Failed jobs

Every job is retried 5 times with a growing delay (about 3 s, 18 s, 83 s, 4 min). After the last failure the job is kept as failed. Signed in, the dashboard shows a red banner with the count of jobs that failed in the last 24 hours, linking to **Failed jobs** (`/jobs/failed`): the time, job, queue, and error of each, newest first (the newest 100). The page is read-only. Retrying or discarding a failed job is done from the server console for now.

## Logs

In production the server writes one JSON object per line to standard output:

```json
{"time":"2026-11-02T13:44:51.432Z","level":"INFO","message":"request completed","request_id":"…","host_id":12,"report_id":"…","event":"request","method":"POST","controller":"Api::V1::InventoryReportsController","action":"create","status":200,"duration_ms":28.6}
```

`request_id` is the `X-Request-Id` response header and the `request_id` in every API error body. To trace an agent report, search the log for its `report_id` or the request id the agent logged. Query strings, headers (including `Authorization`), and request bodies are never logged; secret-like parameters are filtered.

## Retention

History older than the retention window is deleted once a day (03:17 server time) in batches: inventory, config, and package snapshots, recent report ids, host status events, CIS result changes, report requests, advisory refresh attempts, and vulnerability findings resolved before the window. Each host's newest snapshot of each type and newest status event are always kept, and so are current CIS results, open and reopened findings, the newest refresh attempt, advisory and triage data, and their imports. Audit entries are never deleted.

```sh
bin/rails settings:show                  # shows retention.days (default 90)
bin/rails settings:retention DAYS=120    # 7 to 3650; audited
```

A dry run (counts only) from the Rails console: `RetentionPruneJob.perform_now(dry_run: true)`. The log line `[retention] deleted … older than …` states the counts of every run.

## Advisory data

The server downloads OSV advisory data every 6 hours (`FLEET_ADVISORY_FEED_URL`, outbound HTTPS to `storage.googleapis.com` by default; `cmdb/README.md`, "Advisory data"). The fleet page says when each ecosystem's data was last updated, and shows a warning when it is older than `FLEET_ADVISORY_MAX_AGE_HOURS` (48 by default) or has never been refreshed. Until then, vulnerability findings may be missing.

- **A failed refresh** is retried 5 times with backoff, then appears on the failed-jobs banner and page as `AdvisoryFeedRefreshJob`, in `/health` as `failed_jobs`, and in the audit log as "Advisory import failed" with the reason.
- **A refresh held back** ("The last advisory refresh was held back"): the feed's archive would have marked more than 10% of an ecosystem's advisories withdrawn (`FLEET_ADVISORY_WITHDRAW_SHARE`), so nothing was imported and the data may be going stale. It is not a failed job and is not retried. Check the feed (a truncated or wrong archive does this); if the withdrawals are right, confirm the counts on the refusal's page on the Data sources page, or run `ALLOW_WITHDRAWALS=<ecosystem>:<count> bin/rails advisories:refresh` with the counts it prints. `bin/rails advisories:import FULL=1` refuses the same way and takes the same `ALLOW_WITHDRAWALS`.
- **To refresh now:** `bin/rails advisories:refresh`. To see freshness and the last import: `bin/rails advisories:status`.
- **A failed upload import** (Data sources page) is retried 5 times with backoff unless the file cannot be read, then appears on the failed-jobs page as `AdvisoryUploadImportJob`, with the import failed and its reason on the page and in the audit log. An upload whose job never finished is failed and its stored file deleted after an hour by `AdvisoryUploadPruneJob`.
- **A server without internet access:** set `FLEET_ADVISORY_FEED_URL=` (empty). Download `all.zip` elsewhere, copy it over, and run `bin/rails advisories:import FILE=all.zip FULL=1`, not by upload: uploads are for small files (up to 64 MiB), and the Debian archive is about 80 MB and growing. `FULL=1` says it is the complete data set, so it counts as a refresh. A single advisory file adds data but does not.
- **Debian triage** (P2-S16): `DebianTriageRefreshJob` downloads the Debian Security Tracker's JSON every 6 hours, 15 minutes after the OSV refresh (`FLEET_DEBIAN_TRACKER_URL`, outbound HTTPS to `security-tracker.debian.org`; `cmdb/README.md`, "Debian triage"). It only annotates findings, so a failure never affects OSV data, matching, or counts; findings then say Debian's triage is not available once it is older than `FLEET_ADVISORY_MAX_AGE_HOURS`. A failed refresh is retried 5 times, then appears on the failed-jobs page as `DebianTriageRefreshJob` and in the audit log as "Debian triage import failed". A refresh held back (the document would drop more than 10% of a release's entries) keeps that release's data, is audited as "Debian triage import held back", and is not a failed job; if the drop is right, run `bin/rails advisories:triage_refresh` with the `ALLOW_DROPS=` it prints. Without internet access, set `FLEET_DEBIAN_TRACKER_URL=` (empty), download the file elsewhere, and run `bin/rails advisories:triage_import FILE=json`.
