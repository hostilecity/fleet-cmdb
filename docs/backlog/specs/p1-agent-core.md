# P1-AGENT-CORE: Agent config, HTTP client, and enroll command

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-A01: Agent configuration, state directory, logging, and CLI

### Scope

- Subcommands: `run` (default), `enroll` (implemented in [P1-A03](p1-agent-core.md)), `check-config`, and `--version`.
- TOML config: server URL (must be `https`), credential, heartbeat interval, inventory interval, log level, optional `ca_file` (not needed with the default Let's Encrypt certificate, [DEC-05](../../decisions/0005-hosting-tls-deployment.md)). Validation with clear messages and minimum and maximum bounds on intervals. No option exists to disable certificate verification; a test asserts an `insecure` key is rejected as unknown.
- The credential is wrapped in a type that redacts itself in `Debug` and `Display`, so it cannot leak into logs by accident.
- Config file permission check at startup: refuse or warn loudly if readable by group or others (behaviour per [DEC-03](../../decisions/0003-agent-privilege.md)).
- State directory (default `/var/lib/fleet-agent`) created if missing, with strict permissions; loss of the directory must not break enrollment.
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
- Retry policy: exponential backoff with jitter and a cap; the agent keeps running through any outage. `401`, `403 reenrollment_required`, and `426` are logged plainly and backed off to a long interval rather than retried tightly. For `reenrollment_required` the log line tells the operator to run `fleet-agent enroll --force` with the new token.
- Request timeouts; bounded response size.
- Reused connection where practical.

### Acceptance criteria

- [ ] A server with an untrusted certificate is refused (test with a local TLS server)
- [ ] The backoff sequence is capped, jittered, and resets after success (unit test with a fake clock)
- [ ] A `426` response produces a clear log line and the agent keeps running
- [ ] A `401` response never causes a tight retry loop

## P1-A03: Agent enroll command

### Scope

- `fleet-agent enroll --server <url> --token <token> [--ca-file <path>]` redeems the token against `POST /api/v1/enroll`.
- Writes the config file atomically (temporary file and rename), mode `0600`, owned by the service account per [DEC-03](../../decisions/0003-agent-privilege.md).
- Refuses to overwrite an existing credential unless `--force` is passed (re-enrollment).
- Reads the token from an environment variable or standard input as well as the flag, so it need not appear in the process list.
- Prints success without echoing the credential; clear error messages for expired or used tokens and for TLS failures.

### Acceptance criteria

- [ ] After `enroll`, `run` authenticates without further steps
- [ ] The resulting file has the right mode and ownership
- [ ] A failed enroll leaves no partial or empty config file
- [ ] Neither the token nor the credential appears in output or logs
