# ADR 0024: The server's TLS certificate comes from Cloudflare's Origin CA, and agents trust it from their build

- Status: Accepted (owner, #137, 2026-11-08)
- Decision issue: #137
- Requirements: `NFR-1`, `DEC-05`
- Supersedes in part: [ADR 0005](0005-hosting-tls-deployment.md), its third decision (the agent hostname's Let's Encrypt certificate through DNS-01, "so agents trust it with no custom CA") and its first consequence; [ADR 0023](0023-deploy-with-github-actions.md), its second decision (the tunnel reaching the server over plain HTTP on port 80) and the consequence about port 80. The rest of both stands.

## Context

The dashboard has a public hostname (for example `fleet.example.com`) that Cloudflare publishes through a tunnel whose connector runs on another VM. The server's VM has an internal hostname (for example `fleet-vm.example.com`) that is reachable only on the owner's network and VPN. The tunnel connects to that internal hostname over HTTPS. Agents run on VMs on the same internal network, so the internal hostname is also the agent hostname. One certificate for the internal hostname therefore serves both the tunnel and the agents: the tunnel checks the certificate against the internal hostname and passes the browser's hostname on, which is how the app tells dashboard requests from agent requests (DEC-05's host separation, unchanged).

A publicly trusted certificate for an internal hostname needs Let's Encrypt's DNS-01 challenge. That means a Cloudflare API token on the VM that can edit every record in the zone, because Cloudflare cannot limit a token to one record. The owner prefers not to keep a standing credential that can rewrite the zone on the server (zero trust). Nor did they want to run their own certificate authority and guard its key.

## Decision

- **Certificate.** The server's certificate is a Cloudflare Origin CA certificate for the internal hostname, created once in the Cloudflare dashboard (validity of the owner's choosing, up to 15 years). Its certificate and private key are GitHub secrets of the `production` environment. No DNS token is involved.
- **Serving.** The server serves HTTPS itself with that certificate. No proxy container is added. Port 443 is the only port it publishes; plain HTTP on port 80 is no longer published. The tunnel's origin is `https://<internal hostname>`. `cloudflared` trusts Cloudflare's Origin CA itself.
- **Agent trust.** The agent trusts Debian's system store **plus** Cloudflare's two Origin CA roots (ECC and RSA), compiled into every build from `agent/trust/`, plus the optional `ca_file`. The roots are part of each signed release. There is still no way to turn verification off (NFR-1).
- **Rotation.** A new or retired root ships in an agent release that is rolled out **before** the server's certificate moves to it, because agents fetch updates over the same connection whose certificate they check. Renewing the server's certificate under the same root needs no agent change.

## Consequences

- No credential on the server can change DNS, and there is no renewal automation to fail: the owner renews the certificate in Cloudflare and updates two secrets before it expires. The dashboard shows when it expires.
- Both Origin CA roots expire on **2029-08-15**. Cloudflare must publish new roots before then; the agent release that adds them goes out before the server's certificate is reissued under them (`agent/trust/README.md` has the steps). An agent that is offline through the whole rotation needs a manual reinstall.
- Cloudflare holds the Origin CA's key, so Cloudflare, or anyone who controls the owner's Cloudflare account, could issue a certificate for the internal hostname. That is the same party that already terminates dashboard traffic. Hostname verification still applies, and Cloudflare issues Origin certificates only for names in the requesting account's own zones.
- Every agent build trusts Cloudflare's Origin CA for whatever server it is pointed at, not only this fleet's. Someone building the agent for another server keeps working through the system store, and can remove the files from `agent/trust/` in their own build.
- Agent traffic stays on the internal network; the tunnel hop between the two VMs is now encrypted too.
- Rejected: Let's Encrypt through DNS-01 (a zone-wide DNS token on the server); a private CA of the owner's own (a CA key to guard and a `ca_file` on every VM); routing agents through the tunnel with Access service tokens (an internet-facing agent API, Cloudflare reading every report, and agent changes).
