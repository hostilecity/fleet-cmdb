# Agent releases

How agent releases are built, signed, published, and verified, and how the release key is handled ([P1-PACKAGING](backlog/specs/p1-packaging.md), [ADR 0018](decisions/0018-signed-agent-updates.md), signature format in [ADR 0021](decisions/0021-release-signature-format.md)). The workflow is `.github/workflows/agent-release.yml`.

## What a release is

A release is a GitHub release for a tag `agent-v<version>`, for example `agent-v1.2.0`, with four assets:

| Asset | What it is |
|---|---|
| `fleet-agent-<version>-x86_64-unknown-linux-musl` | The static binary ([DEC-01](decisions/0001-fleet-profile.md)) |
| `fleet-agent-<version>-x86_64-unknown-linux-musl.manifest.json` | The manifest: what the binary is |
| `fleet-agent-<version>-x86_64-unknown-linux-musl.manifest.json.minisig` | The manifest's signature |
| `SHA256SUMS` | `sha256sum` lines for the binary and the manifest |

`<version>` is strict [SemVer](https://semver.org/) without build metadata (`1.2.0`, `1.3.0-rc.1`), equal to `version` in `agent/Cargo.toml` and to what `fleet-agent --version` prints. A version with a pre-release part is published as a GitHub pre-release.

### The manifest

One line of JSON, written by `agent/scripts/release-manifest.sh`:

```json
{"format":"fleet-agent-release-manifest/1","version":"1.2.0","target":"x86_64-unknown-linux-musl","sha256":"<64 lowercase hex digits>","size":3357672}
```

| Field | Rule |
|---|---|
| `format` | Exactly `fleet-agent-release-manifest/1`. A change to the fields means a new format, which older agents refuse |
| `version` | Strict SemVer, no build metadata, at most 64 characters |
| `target` | `x86_64-unknown-linux-musl`, the only target |
| `sha256` | SHA-256 of the binary, 64 lowercase hexadecimal digits |
| `size` | Size of the binary in bytes, 1 to 64 MiB |

No other field is allowed. The signature covers the exact bytes of the file, so the manifest is never re-serialised: agents verify the bytes they downloaded, then parse them.

### The signature

The manifest is signed with [minisign](https://jedisct1.github.io/minisign/): Ed25519 over the BLAKE2b-512 hash of the file (minisign's default, pre-hashed mode), plus a second Ed25519 signature over the first one and the *trusted comment*, so the comment (`fleet-agent <version> <target> release manifest`) cannot be altered either. The `.minisig` file is minisign's standard four-line format, and the public keys are minisign's standard `.pub` files. minisign's legacy, not pre-hashed, mode is refused. Why minisign rather than another format: [ADR 0021](decisions/0021-release-signature-format.md).

### What an agent accepts

The agent code is `agent/src/release/`; the updater (P1-AGENT-UPDATE) and `fleet-agent verify-release` both use it. A release is accepted only if, in this order:

1. the signature verifies against one of the release public keys built into the agent (below);
2. the manifest then parses and follows every rule in the table above;
3. the binary has exactly the manifest's size and SHA-256.

Nothing in the manifest is used before its signature has verified. The updater also refuses any version not newer than the running one ([ADR 0018](decisions/0018-signed-agent-updates.md)).

**Freshness is not covered (known limit).** A signed manifest never expires. The no-downgrade rule stops an older release being pushed, but nothing in the release stops someone who controls what an agent is offered from holding back a newer release (a freeze), or from offering a release that has since been withdrawn. A signature cannot be revoked, so a bad release is withdrawn by publishing a higher version. This is acceptable while the server that chooses rollouts is trusted (ADR 0018). Expiring, signed release metadata, as in TUF, is the fix to revisit before agents trust more than one operator's servers.

## Verifying a download by hand

**Where it was built:** every release binary has GitHub build provenance (SLSA), showing the workflow run and commit that built it:

```sh
gh attestation verify fleet-agent-1.2.0-x86_64-unknown-linux-musl --repo hostilecity/fleet-cmdb
```


With an agent you already trust (it checks against the keys built into it, and changes nothing):

```sh
fleet-agent verify-release \
  --manifest fleet-agent-1.2.0-x86_64-unknown-linux-musl.manifest.json \
  --signature fleet-agent-1.2.0-x86_64-unknown-linux-musl.manifest.json.minisig \
  --binary fleet-agent-1.2.0-x86_64-unknown-linux-musl
```

It exits `0` and prints the version, the key that signed it (`current` or `next`), and the binary's SHA-256; `1` with the reason if anything does not match; `2` on a usage error. Without an agent, use minisign and the public key from `agent/release-keys/current.pub` in this repository, then the checksums:

```sh
minisign -V -p current.pub -m fleet-agent-1.2.0-x86_64-unknown-linux-musl.manifest.json
sha256sum -c SHA256SUMS
```

`SHA256SUMS` alone only shows the download is complete; the signature shows it is a release.

## Release keys

### Where they are

| What | Where | Who can read it |
|---|---|---|
| Current public key | `agent/release-keys/current.pub`, compiled into the agent | Everyone |
| Next public key | `agent/release-keys/next.pub`, compiled into the agent | Everyone |
| Current private key (encrypted) and its password | The `release` environment's secrets `AGENT_RELEASE_SIGNING_KEY` and `AGENT_RELEASE_SIGNING_KEY_PASSWORD` | Only the `sign` job, after the owner approves the run |
| Backups of both private keys (encrypted) and their passwords | Offline, with the owner (for example a password manager plus an offline copy) | The owner |

Each `.pub` file is either exactly the two lines minisign writes, or only `#` comment lines, meaning no key. Until the owner generates the first key the files hold no key: then the agent accepts no release, the release workflow refuses to run, and Agent CI still passes (its dry run uses a throwaway key).

A private key is never committed, never printed in CI, and never used in tests: the tests and the CI dry run generate throwaway keys and discard them. The next private key is not stored in GitHub at all until a rotation makes it current, so a compromise of GitHub cannot reach it.

### Generating the keys (once, by the owner)

On a trusted machine with minisign 0.11 or later (`apt install minisign`). minisign asks for a password for each key; use a different strong password for each and keep them with the backups.

```sh
umask 077
minisign -G -p current.pub -s current.key -c "fleet-agent release key 1"
minisign -G -p next.pub -s next.key -c "fleet-agent release key 2"
```

1. Copy `current.pub` over `agent/release-keys/current.pub` and `next.pub` over `agent/release-keys/next.pub`, in a pull request. Both are public. The tests check that the files parse and differ.
2. In **Settings > Environments > release > Environment secrets**, add `AGENT_RELEASE_SIGNING_KEY` with the **second line only** of `current.key` (the base64 line; the workflow adds the comment line back), and `AGENT_RELEASE_SIGNING_KEY_PASSWORD` with its password. A single-line secret is masked reliably in logs. Never add them as repository secrets.
3. Back up `current.key`, `next.key`, and both passwords offline, then delete the key files from the machine.

The server checks imported releases against the same public keys, from its own configuration ([P1-RELEASES](backlog/specs/p1-releases.md)): set `FLEET_RELEASE_KEY_CURRENT` (and, once there is one, `FLEET_RELEASE_KEY_NEXT`) to the contents of the `.pub` files (`cmdb/README.md`, "Agent releases"). After a rotation (below), update the server's keys in the same change as `current.pub`.

### Rotation

An agent trusts only the keys it was built with, so a new key must ship in a release before any release is signed with it ([ADR 0018](decisions/0018-signed-agent-updates.md)):

1. **Ship the next key.** It is already in `next.pub` from the start; after a rotation, generate a new next key as above and put its `.pub` in `next.pub`. Release as usual (signed with the current key).
2. **Wait** until every host runs a release that contains it (the dashboard's agent versions). A host that misses this keeps working but can no longer be updated remotely; re-running `fleet-agent install` with a new binary upgrades it by hand (NFR-4).
3. **Switch.** In one pull request, move the next key's `.pub` into `current.pub` and the following key into `next.pub` (or leave it empty). Put the next private key and its password into the `release` environment's secrets, replacing the old ones. The next release is signed with the new key; agents accept it because it was their `next` key.
4. Destroy the old private key and its backups.

Releases are always signed with the key in `current.pub`: the workflow verifies with exactly that key, so a mistake in step 3 stops the release instead of publishing one that agents refuse.

**If the current private key leaks:** remove the environment secrets at once (no release can be signed meanwhile), then do step 3 straight away with the uncompromised next key, and release. Agents that trusted the leaked key keep trusting it until they run that release, so roll it out with priority. The no-downgrade rule stops a leaked key from being used to push an old release, but not a malicious new one; that window is why the next key is kept offline. **If both keys leak**, the remote update path cannot be trusted: stop rollouts and reinstall agents by hand with a release built with new keys.

## Making a release

1. In a pull request, set `version` in `agent/Cargo.toml` to the new version and run `cargo build` so `Cargo.lock` follows. Merge it once Agent CI passes.
2. Tag the merge commit on `main` and push the tag:

   ```sh
   git tag agent-v1.2.0 <commit on main>
   git push origin agent-v1.2.0
   ```

3. **Test, build, and rebuild** run in parallel, without secrets:
   - **Test** runs the test suite in its own job, so test code never runs where the release binary is built.
   - **Build** refuses the tag unless it is `agent-v<SemVer>`, matches `Cargo.toml`, points at a commit on `main`, and `current.pub` holds a key. It builds the static binary reproducibly (`agent/scripts/build-release.sh`: build paths are remapped out of the binary), checks `--version`, writes the manifest and `SHA256SUMS`, and puts both in the run's summary.
   - **Rebuild** builds the same commit again on a separate runner.
4. **Sign** first requires the build and the rebuild to have produced byte-identical binaries, so a tampered build would have to compromise two runners identically. It then waits for approval: in **Actions**, open the run, compare the summary (version, size, SHA-256) with what you meant to release, and approve the `release` environment. The job sees only the manifest, writes the key to a private temporary file for the one `minisign -S` command, and deletes it.
5. **Publish** verifies the signature twice, with the new binary's own `verify-release` and with minisign against `current.pub`, checks the manifest names the tag's version and the binary both builds made, records build provenance for the binary, and creates the GitHub release.

A failed run publishes nothing; fix the cause and re-run the failed jobs, or delete the tag and tag again. A published release is never replaced: release a new version instead.

## Getting a release to the fleet

Once the release is published, an operator imports it on the dashboard's **Agents** page, by version from GitHub, or by uploading the binary, the manifest, and the `.minisig` for a server without internet access. The server verifies it as an agent would, refuses it with the reason if anything does not match, and audits either outcome. It then serves the three files on the agent hostname (`/api/v1/releases/<version>/...`), and **Install an agent** shows the commands for it. Rolling it out to running agents is P1-UPDATES.

## Repository settings the release relies on

ADR 0018 makes the owner's GitHub account and the `release` environment the trust anchor. The owner sets these once; they are not in the repository, so they are listed here and checked on each release:

- **Account:** two-factor authentication on the owner's account (ideally a security key).
- **Environment `release`** (Settings > Environments):
  - Required reviewers: the owner. (Leave "Prevent self-review" off while the owner is the only reviewer, or the owner cannot approve a release they tagged.)
  - Deployment branches and tags: **Selected branches and tags**, with only the tag pattern `agent-v*`, so no branch can run a job in this environment.
  - Environment secrets: `AGENT_RELEASE_SIGNING_KEY` and `AGENT_RELEASE_SIGNING_KEY_PASSWORD`, and no others.
- **Tag ruleset** (Settings > Rules > Rulesets > New tag ruleset): target `agent-v*`; restrict creations, restrict updates, restrict deletions, and block force pushes; bypass list: the owner only. Only the owner can then start a release, and a published tag cannot be moved to other code.
- **Branch protection on `main`:** pull requests required, Agent CI and Server CI required, no force pushes, so the tag check "on main" means "reviewed and tested".
- **Actions:** default workflow permissions read-only (each job asks for what it needs); fork pull requests never get secrets (GitHub's default).

## What CI does without a tag

Agent CI (`.github/workflows/agent-ci.yml`) runs on every pull request and push to `main`. It builds the static musl binary, checks it is static and reports the `Cargo.toml` version, and uploads it as an unsigned workflow artefact on `main`. It then runs the whole release pipeline as a dry run with a key pair it generates and discards: embed the throwaway public key, build, write the manifest, sign it with minisign, verify it with `verify-release`, and check a changed manifest is refused. It never sees the release key, so an untagged build is never signed. It builds the binary a second time in another directory and fails if the two differ, so a change that breaks reproducible builds is caught before a release needs one. It also checks the systemd unit with `systemd-analyze` (`agent/scripts/check-unit.sh`), and runs the musl binary under the unit's sandbox on the runner's systemd against a local stand-in for the agent API (`agent/scripts/sandbox-smoke.sh`): the sandboxed run must report every fact an unsandboxed run does, with no new warning.
