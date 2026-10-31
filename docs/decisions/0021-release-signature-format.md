# ADR 0021: Release signature format: minisign

- Status: Proposed (P1-PACKAGING, #15; for the owner's acceptance)
- Decision issue: #15
- Requirements: `FR-S.5`, `FR-1.6`, `NFR-1`
- Refines: [ADR 0018](0018-signed-agent-updates.md), which decided Ed25519 release signatures over a manifest, signed in CI, with current and next keys built into the agent. It did not name a file format.

## Context

ADR 0018 needs a signature that the agent (a static, root-run Rust binary with a short dependency list), the server's release import (Ruby, [P1-RELEASES](../backlog/specs/p1-releases.md)), CI (a GitHub runner), and an operator by hand can all check. The format should be a well-established one with existing tools, not one invented here, and should let a signature say which key made it, so that two embedded keys (current and next) work without trial and error.

## Decision

Release manifests are signed with **minisign** in its default, pre-hashed mode: Ed25519 over the BLAKE2b-512 hash of the manifest, plus an Ed25519 signature over that signature and a trusted comment. Keys are minisign key pairs, the private key encrypted with a password (scrypt). The formats, the key handling, and rotation are in [docs/releases.md](../releases.md).

- **CI** signs with the `minisign` package from the runner's distribution.
- **The agent** verifies with the `minisign-verify` crate (verify-only, by minisign's author, no dependencies; the verifier the Tauri updater uses), with legacy (not pre-hashed) signatures refused.
- **Tests** sign with the `minisign` crate, a test-only dependency, and throwaway keys.
- **The server** can verify with Ruby's OpenSSL (Ed25519 and BLAKE2b-512) after reading the two short base64 lines; that is P1-RELEASES' choice.

Rejected:

- Raw Ed25519 over the manifest with an own encoding: a format invented here, without the key id, tools, or documentation minisign brings.
- OpenSSH signatures (`ssh-keygen -Y sign`): also Ed25519 and well known, but the Rust verifiers pull in much more code (RustCrypto `ssh-key` with `ed25519-dalek`) for a root-run agent.
- Sigstore / cosign: keyless signing ties trust to an online transparency log and an identity provider, and its key-based mode uses ECDSA P-256 by default; ADR 0018 chose an Ed25519 key held in the release environment.
- GPG: large tooling, complex key format, poor fit for a small static verifier.
- `signify` (OpenBSD): the same idea as minisign, but with less tooling outside OpenBSD and no maintained Rust verifier.

## Consequences

- One new runtime dependency, `minisign-verify`, which carries its own Ed25519 and BLAKE2b implementation instead of using `ring`, which the agent already links for TLS. It is small and verify-only, but it is a second implementation of Ed25519 in the binary and is not separately audited. If the owner prefers only `ring` for signatures, the alternative is minisign's legacy mode (pure Ed25519, which `ring` verifies) with an own parser of the minisign format; that trades a deprecated mode and own code for one less dependency.
- Anyone can verify a release with stock minisign and the public key in the repository.
- Changing the format later means a new manifest `format` and a release that understands both, shipped before the change (as for a key rotation).
