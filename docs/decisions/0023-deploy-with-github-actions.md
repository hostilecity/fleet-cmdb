# ADR 0023: Deploy the server with GitHub Actions as one container

- Status: Accepted (owner, review of #88, 2026-11-07)
- Decision issue: #88
- Requirements: `NFR-1`, `NFR-4`
- Supersedes in part: [ADR 0005](0005-hosting-tls-deployment.md), its first decision ("Deployment is Docker Compose on one homelab machine") and its consequence listing the compose stack. The rest of ADR 0005 stands: the dashboard behind the Cloudflare tunnel and Access, and the private agent API with a publicly trusted certificate.

## Context

The owner already runs PostgreSQL in its own container on the server, from a separate project, and runs the Cloudflare tunnel connector on another VM. Another of their apps deploys from a GitHub Actions workflow on a self-hosted runner, which builds the image on the server and runs one container on the database's Docker network. A Compose stack that also bundled PostgreSQL, the tunnel connector, and a TLS proxy duplicated what the server already has.

## Decision

- `.github/workflows/cd.yml` deploys the server. A self-hosted runner on the LAN connects over SSH, ships the commit, builds the image on the server, and runs one container, `fleet-cmdb`. The container joins the existing PostgreSQL container's network, keeps `/rails/storage` in a volume, and publishes port 80. Settings come from a GitHub environment, passed through an env file written over SSH standard input, never on a command line.
- The tunnel on another VM reaches the server over plain HTTP on port 80, behind Cloudflare Access. No proxy is trusted for forwarded headers.
- The agent hostname's TLS (ADR 0005's private agent API) is decided and built in #137. Backups in this deployment get their own issue.
- Rejected: the Compose stack with Traefik and a second TLS entrypoint for the remote tunnel. It is safer on the LAN, but much larger than the owner wants to run.

## Consequences

- The deployment is a few dozen lines of workflow. Deploy CI checks the image as the workflow runs it.
- Port 80 is plain HTTP on the LAN: anyone there reaches the dashboard without Access (Google sign-in still applies) until a firewall rule limits it to the tunnel VM. The guide recommends that rule.
- A self-hosted runner on a public repository must not run fork pull requests unapproved.
- No agent can be installed until #137 serves the agent hostname with TLS. `/health` reports 503 until backups exist.
