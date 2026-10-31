# P1-RELEASES: Signed release import, downloads, and the install page

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

Decided in [ADR 0018](../../decisions/0018-signed-agent-updates.md). The release signing itself happens in CI ([P1-PACKAGING](p1-packaging.md)).

## P1-S15: Release import and storage

### Scope

- **An `agent_releases` table:** version, target, SHA-256, size, the signed manifest, its signature, the import time, and the importing operator.
- **Import paths.**
  - From the GitHub release for a tag, by a background job. The server needs outbound HTTPS to `github.com` for this.
  - By uploading the binary, manifest, and signature, for networks without internet access. Binaries live on a persistent volume, not in the database (Active Storage is not used).
- **Verification on import.** The manifest signature is checked against the release public keys in server configuration, the checksum and size are checked, and the version must be strict SemVer. A failing release is refused and the failure audited. This check is defence in depth: agents verify independently.
- **No deletion.** Releases are never deleted while any host runs them or a rollout targets them.
  - Enforced for hosts by the model and a database trigger (`agent_releases_guard`), which also makes releases immutable. There is no delete action in the dashboard. Rollouts reference the release with a restricting foreign key ([P1-UPDATES](p1-updates.md)).
- **Where operators do it:** the Agents page of the [P1-D06](p1-dash-actions.md) mockups (`agents.html`): the releases table, "Import a release from GitHub", and the upload. A GitHub import's progress and outcome are kept in `agent_release_imports` and shown there, since the job runs after the request.

### Acceptance criteria

- [ ] A release signed by the release key imports; a wrong signature, a modified binary, or an unknown key is refused with a clear reason
- [ ] Imports are audited with the operator as actor

## P1-S16: Release downloads on the agent hostname

### Scope

- **`GET /api/v1/releases/<version>/manifest`, `.../signature`, and `.../binary`** on the agent hostname only.
  - Unauthenticated, because binaries are public and the installer has no credential yet, but rate-limited per address.
  - Served with `ETag` and `Content-Length`, and range requests so an interrupted download can resume.
  - Exempt from the minimum-version check (FR-S.5).
- **Location-independent.** Manifest and binary URLs reach agents in the update directive, so a later move to a CDN or object store needs no agent change ([ADR 0019](../../decisions/0019-scale-direction.md)).

### Acceptance criteria

- [ ] Downloads are not served on the dashboard hostname, and a resumed download yields a byte-identical binary

## P1-D08: Agent install page

### Scope

- **A dashboard page "Install an agent"**, following the approved mockups in [P1-D06](p1-dash-actions.md). It shows the current release and the exact commands to copy:
  - download from the agent hostname;
  - check the SHA-256;
  - run `sudo ./fleet-agent install --server …`.

  It also shows the pre-registered-token variant for unattended installs, and what to expect next (the approval URL and code).
- **Clear enough to use without other documentation (NFR-4).** Validated by following it on a clean VM.

### Acceptance criteria

- [ ] Copying the commands from the page onto a clean Debian 13 VM installs the agent with no other instructions
- [ ] The page shows the checksum of exactly the release it links to
