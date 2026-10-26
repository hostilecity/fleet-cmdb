# P1-ACCESS: Operator sign-in and host-based route separation

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P1-S01: Operator accounts and dashboard sign-in (Google OAuth allowlist)

### Context

The dashboard must require sign-in with no anonymous view of fleet data, and must not hard-code a single operator. [DEC-06](../../decisions/0006-operator-authentication.md) chose Google OAuth with an email allowlist (as in `homealert`) and no application passwords.

### Scope

- `Operator` model keyed by Google account (subject id and email), plus an allowlist of permitted email addresses held by the server. Only a **verified** email present on the allowlist can sign in; everyone else is rejected without creating a record.
- OmniAuth Google OAuth2 with CSRF protection (`omniauth-rails_csrf_protection`), `state` validation, and the ID token validated.
- Secure, HTTP-only, same-site session cookies, idle and absolute session timeouts, and sign-out. The dashboard hostname is served over TLS by Cloudflare, so Rails runs with `assume_ssl` and `force_ssl` behind the trusted proxy.
- Authentication required by default for every dashboard controller. Pages that must be public (the sign-in page, the OAuth callback, `/up`) opt out explicitly.
- No sign-up route and no password fields anywhere. A rake task adds an email to the allowlist (`operators:allow EMAIL=...`) and one lists or removes entries. The first operator is added this way.
- The current operator is available to the audit log as the actor ([P1-S03](p1-hosts.md)). Allowlist changes are audited.
- Cloudflare Access sits in front of the dashboard hostname ([DEC-05](../../decisions/0005-hosting-tls-deployment.md)); the app does not rely on it. Optionally validate the Access JWT as a second check (decide in the PR).

### Acceptance criteria

- [ ] A route-enumeration spec proves every non-API dashboard route redirects anonymous requests to sign-in, except an explicit allowlist
- [ ] An email not on the allowlist, or unverified at Google, cannot sign in (spec with stubbed OAuth responses)
- [ ] There is no route that creates an operator outside the allowlist flow and no password field in the schema
- [ ] Two allowlisted operators can sign in independently
- [ ] OAuth tokens and session ids never appear in logs (spec over captured log output)

## P1-S13: Host-based route separation: dashboard on the public host, agent API on the private host

### Context

[DEC-05](../../decisions/0005-hosting-tls-deployment.md): the dashboard is reachable through the Cloudflare tunnel, but the agent API must never be. The tunnel configuration is a second line of defence; this issue makes the application itself refuse to serve the wrong routes on the wrong hostname.

### Scope

- Two configured hostnames (dashboard host and agent host), read from environment.
- Routing constraints: `/api/v1/*` is served only when the request host is the agent host; every dashboard route, the OAuth callback, and Action Cable are served only on the dashboard host. Anything else gets a `404` with no body detail.
- Host header handling is strict (`config.hosts`) and honours the trusted proxy's forwarded host only from configured proxy addresses.
- `/up` and `/health` are served on the agent host and on a private path that is not published by the tunnel; document which.
- Tests for every combination: API on dashboard host, dashboard on agent host, unknown host, forged `X-Forwarded-Host`.

### Acceptance criteria

- [ ] A request for any `/api/v1` route with the dashboard hostname returns `404`
- [ ] A request for a dashboard route with the agent hostname returns `404`
- [ ] A spoofed `Host` or `X-Forwarded-Host` header cannot cross the boundary
- [ ] The behaviour is covered by request specs that run in CI
