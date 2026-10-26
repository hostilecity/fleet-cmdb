# ADR 0005: Hosting, TLS, and deployment

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-05
- Requirements: `docs/requirements.md`, section 10

## Context

Agents must verify the server certificate with no opt-out. The owner already publishes homealert through Cloudflare.

## Decision

- Deployment is **Docker Compose** on one homelab machine.
- The **dashboard** is published through a **Cloudflare tunnel**, which terminates TLS, with **Cloudflare Access** in front of it.
- The **agent API is private**: a separate hostname resolving to a LAN address, served with a Let's Encrypt certificate issued by DNS-01 through Cloudflare, so agents trust it with no custom CA. It is never routed through the tunnel.
- Rails enforces the separation with **host-based route constraints**: dashboard routes answer only on the dashboard hostname and `/api/v1` only on the agent hostname, covered by tests.

## Consequences

- The agent's optional `ca_file` remains available but is not needed in the default setup.
- The compose stack contains Rails, PostgreSQL, a TLS proxy for the agent hostname (with the Cloudflare DNS challenge), and the tunnel connector.
- Cloudflare sees dashboard traffic in plaintext at its edge; agent traffic never leaves the LAN.
- Rails must trust the proxy for client addresses (`assume_ssl`, trusted proxies) and set `config.hosts` to the two hostnames.
