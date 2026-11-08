# Certificate authorities compiled into the agent

The agent trusts Debian's system store, the certificates in this directory, and the optional `ca_file` ([ADR 0024](../../docs/decisions/0024-cloudflare-origin-ca-for-the-server.md)). These files are compiled into every build (`EMBEDDED_ROOTS` in `src/client.rs`), so they are covered by each release's signature. Only public certificates belong here, never a key.

| File | Certificate | SHA-256 fingerprint (DER) | Expires |
|---|---|---|---|
| `cloudflare-origin-ecc.pem` | CloudFlare Origin SSL ECC Certificate Authority | `AA:63:69:7A:22:76:4B:67:B2:13:4C:E1:4C:B5:69:0E:A3:36:94:0B:93:98:61:13:F4:95:45:91:78:32:D8:0D` | 2029-08-15 |
| `cloudflare-origin-rsa.pem` | CloudFlare Origin SSL Certificate Authority | `D3:C7:E8:5C:91:70:7F:C0:A1:2A:BC:5D:88:26:67:47:AA:4F:A8:E7:B1:62:F6:33:FF:B3:C9:D9:89:94:76:20` | 2029-08-15 |

Both files are copied unchanged from Cloudflare's documentation repository (`cloudflare/cloudflare-docs`, `public/ssl/static/origin_ca_ecc_root.pem` and `origin_ca_rsa_root.pem`, served at `developers.cloudflare.com/ssl/static/`). On 2026-11-08 they matched the copies `cloudflared` itself trusts (`cloudflare/cloudflared`, `tlsconfig/cloudflare_ca.go`). Check a fingerprint with `openssl x509 -in cloudflare-origin-ecc.pem -noout -fingerprint -sha256`. The agent's tests pin both fingerprints, so changing a file means changing the test too.

## Changing a root

Agents download their updates over the same HTTPS connection whose certificate they check. So a new root must reach the agents **before** the server's certificate uses it:

1. Add the new root here (keep the old one), add it to `EMBEDDED_ROOTS` in `src/client.rs` (which names each file, so a file alone is not compiled in), update the table and the fingerprints in the tests beside it, and release an agent.
2. Roll it out to every host. The Agents page shows each host's version.
3. Only then reissue the server's certificate under the new root and update its secrets.
4. In a later release, remove the retired root: its file, its `EMBEDDED_ROOTS` entry (the build fails if the entry names a missing file), and its fingerprint in the tests.

A host that misses step 2, for example a VM that was powered off, cannot connect after step 3 and needs a manual reinstall.

Renewing the server's certificate under a root that is already here needs no agent change.
