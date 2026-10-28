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
- Typed error mapping from the documented envelope ([DEC-08](../../decisions/0008-api-conventions.md)) including `401` (credential rejected), `403 reenrollment_required` (the host is being re-enrolled; also signalled by `Fleet-Enrollment-State: pending`), `426` (agent unsupported), `429` (honour `Retry-After`), `413`, and `5xx`.
- Retry policy: exponential backoff with jitter and a cap; the agent keeps running through any outage. `401`, `403 reenrollment_required`, and `426` are logged plainly and backed off to a long interval rather than retried tightly. For `reenrollment_required` the log line tells the operator to run `fleet-agent install --reenroll`, or `fleet-agent install --token` with the new token.
- Request timeouts; bounded response size.
- Reused connection where practical.

### Acceptance criteria

- [ ] A server with an untrusted certificate is refused (test with a local TLS server)
- [ ] The backoff sequence is capped, jittered, and resets after success (unit test with a fake clock)
- [ ] A `426` response produces a clear log line and the agent keeps running
- [ ] A `401` response never causes a tight retry loop

## P1-A03: Enroll command (moved)

Replaced by `fleet-agent install` in [P1-A10](p1-agent-install.md) ([ADR 0017](../../decisions/0017-agent-onboarding.md)). The config file written there follows P1-A01: atomic write, mode `0600`, owned per [DEC-03](../../decisions/0003-agent-privilege.md).
