## Summary

<!-- What does this change do, and why? -->

Closes #

<!-- Keep "Closes #N" so merging closes the issue. Use "Refs #N" instead only if more PRs for this issue will follow. -->

## Requirements implemented

<!-- Cite the IDs, e.g. FR-1.4, NFR-1, AC-1.2. Requirement IDs are stable and live in docs/requirements.md. -->

-

## Delivery note

- **Built:**
- **Tested** (specs, commands, or manual checks, and the result):
- **Acceptance criteria covered** (AC-x.y and the test or check that proves each):
- **Decisions / recommended defaults used** (DEC-nn, or "none"):
- **Left incomplete or deferred** (and the issue tracking it):

## Checklist

- [ ] Tests added or updated, and the suite passes locally (`cmdb/bin/ci` and/or `cargo test` in `agent/`)
- [ ] Migrations run forward cleanly from the previous state
- [ ] Documentation updated (setup, configuration, operator workflow) where behaviour changed
- [ ] No secrets, real hostnames, or real addresses in code, fixtures, docs, or this description
- [ ] Nothing out of scope or from a later phase was added
- [ ] API payload changes update `docs/api/` schemas and examples (or: not applicable)
- [ ] Task-related changes: no path lets the server send a command, script, or executable name (or: not applicable)
