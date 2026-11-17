# P1-AGENT-CORE: Agent config and HTTP client

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-A01: Agent configuration, state directory, logging, and CLI

### Scope

- Subcommands: `run` (default), `check-config`, and `--version`. `install` and `uninstall` are [P1-A10](p1-agent-install.md); `self-test` and `update-supervise` are [P1-AGENT-UPDATE](p1-agent-update.md).
- TOML config: server URL (must be `https`), credential, heartbeat interval, inventory interval, log level, optional `ca_file` (not needed with the default Let's Encrypt certificate, [DEC-05](../../decisions/0005-hosting-tls-deployment.md)). Validation with clear messages and minimum and maximum bounds on intervals. No option exists to disable certificate verification; a test asserts an `insecure` key is rejected as unknown.
- The credential is wrapped in a type that redacts itself in `Debug` and `Display`, so it cannot leak into logs by accident.
- Config file permission check at startup: refuse or warn loudly if readable by group or others (behaviour per [DEC-03](../../decisions/0003-agent-privilege.md)).
- State directory (default `/var/lib/fleet-agent`) created if missing, with strict permissions; loss of the directory must not break enrollment.
- Server-directed intervals ([ADR 0019](../../decisions/0019-scale-direction.md)): the config intervals are the starting values and the bounds; an interval from the server is applied only within those bounds (see [P1-AGENT-REPORT](p1-agent-report.md)).
- Structured, timestamped logging suitable for the systemd journal (key=value or JSON lines on stdout), with each report's outcome logged and no credential ever logged.
- Graceful shutdown on `SIGTERM` and `SIGINT`.

### Acceptance criteria

- [ ] A config containing an `http://` server URL is rejected
- [ ] Unit tests prove the credential never appears in `Debug` or log output
- [ ] Invalid and missing config produce actionable errors and a nonzero exit
- [ ] `check-config` validates a config without contacting the server

## P1-A02: Agent HTTP client: TLS, authentication, retry with backoff

### Scope

- HTTPS client using `rustls`; trusts the system roots plus the optional `ca_file`. No code path disables verification.
- Sends `Authorization: Bearer <credential>` and the agent version on every request.
- Typed error mapping from the documented envelope ([DEC-08](../../decisions/0008-api-conventions.md)) including `401` (credential rejected), `403 reenrollment_required` (the host is being re-enrolled; also signalled by `Fleet-Enrollment-State: pending`), `426` (agent unsupported), `429` (`ApiError::RateLimited` carries the envelope code; only a `429 rate_limited` with `Retry-After` is honoured, in every loop, for at most 15 minutes, `RATE_LIMITED_MAX`; any other `429` is transient, #223), `413`, and `5xx` (a `503 overloaded` with `Retry-After` is the server shedding report load, #200: only the report loops honour it, for at most 15 minutes, `RetryPolicy::reports`; for every other loop, and for any other `503`, it is transient, review of #208).
- Retry policy: exponential backoff with jitter and a cap; the agent keeps running through any outage. As built (`agent/src/retry.rs`): the n-th consecutive transient failure waits uniformly in `[1 s, min(5 s * 2^(n-1), 5 min)]` ("full jitter", #200; it was `[d/2, d]` before), so agents back from an outage spread over the whole 5 minutes. An honoured `Retry-After` (a `429 rate_limited`, or a `503 overloaded` in the report loops) is waited in full plus up to 10% (at most a minute), and never less than the backoff; no `Retry-After` holds any loop for more than 15 minutes plus that spread (#221, #223). That cap bounds a broken or forged header; update confirmations (300 s by default) rely on the server's own windows being a minute or less. The installer applies the same rule with its own 60 s cap (`MAX_POLL_BACKOFF`, review of #233): for a `429 rate_limited` the onboarding poll waits out `Retry-After` (and polls 5 s less often), the confirming heartbeat waits it, and a refused enrollment or onboarding start says how long to wait, each at most a minute. Any other `429` is not blamed on the server: the poll and the confirming heartbeat retry it like a network error (one warning), and a refused enrollment, onboarding start, or address check says a proxy, load balancer, or CDN in front of the server refused it, without repeating its wait. `401`, `403 reenrollment_required`, and `426` are logged plainly and backed off to a long interval rather than retried tightly. For `reenrollment_required` the log line tells the operator to run `fleet-agent install --reenroll`, or `fleet-agent install --token` with the new token.
- Request timeouts; bounded response size.
- Reused connection where practical.

### Acceptance criteria

- [ ] A server with an untrusted certificate is refused (test with a local TLS server)
- [ ] The backoff sequence is capped, jittered, and resets after success (unit test with a fake clock)
- [ ] A `426` response produces a clear log line and the agent keeps running
- [ ] A `401` response never causes a tight retry loop

## P1-A03: Enroll command (moved)

Replaced by `fleet-agent install` in [P1-A10](p1-agent-install.md) ([ADR 0017](../../decisions/0017-agent-onboarding.md)). The config file written there follows P1-A01: atomic write, mode `0600`, owned per [DEC-03](../../decisions/0003-agent-privilege.md).
