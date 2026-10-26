# Agent instructions

How to work on this repository. Keep context small: read what a task needs, not the whole backlog.

## Workflow

1. **Pick an open GitHub issue** with no unmet "Blocked by". Issues are short stubs: a goal, the requirement IDs it covers, 2 or 3 acceptance criteria, a link, and blockers.
2. **Read the linked spec first**, `docs/backlog/specs/<issue key>.md`. The repository files are the source of truth for implementation details; the issue is only a pointer. If the issue and the spec disagree, the spec wins.
3. **Read only what the spec points to:** the requirement IDs it covers (search `docs/requirements.md` for the ID) and the ADRs it links in `docs/decisions/`. Do not read the whole requirements document or other specs unless a link sends you there.
4. **Link the issue in every pull request with a closing keyword:** write `Closes #N` in the PR description so merging closes the issue. Use `Refs #N` only when more pull requests for that issue will follow (for example an early mockup PR), and `Closes #N` on the final one. Cite requirement IDs in commit and PR titles (`FR-1.4: evaluate liveness every minute`). Use the pull request template, including its delivery note.
5. **If the work changes behaviour, change the files that describe it in the same pull request:** the spec, `docs/requirements.md`, or a new ADR that supersedes an old one. Never leave the repository and the issue saying different things.
6. An issue may be delivered in several pull requests. Each spec section is a unit of work.
7. **Mockups come first and may be delivered early.** Dashboard issues start with a mockup section (`P1-D01`, `P2-D01`, `P3-D01`) delivering static HTML in `docs/mockups/phase-N/`. Do it as its own pull request (`Refs #N`) even while the issue is still blocked, since mockups need no code from earlier work; the owner approves it before any view is built. Mockup PRs are exempt from the "no later-phase work" rule because they contain no code.

## Commands

- Server (`cmdb/`): use Ruby 3.4.10 through chruby (not the macOS system Ruby). `bin/setup`, then `bin/ci` (rubocop, brakeman, bundler-audit, RSpec). See `cmdb/README.md`.
- Agent (`agent/`): `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
- Backlog tooling: `ruby docs/backlog/import.rb check` validates `docs/backlog/issues.yml` and the specs.

## Non-negotiables

- Do not build anything out of scope (`docs/requirements.md`, section 1) or from a later phase than the issue's milestone.
- The server never sends a command line, script, or executable name to an agent. Tasks are catalog entries plus schema-valid parameters only.
- No OTA or agent self-update. No arbitrary remote shell.
- The agent API is served only on the private agent hostname, never through the dashboard hostname.
- No secrets, real hostnames, or real addresses anywhere in the repository, including issues, fixtures, and examples. Use `vm-01.example.lan`.
- Decisions are recorded in `docs/decisions/`. Do not reverse one in code; propose a new ADR.

## Style

- Cite file paths as `path:line` when discussing code.
- Keep pull requests focused on one issue; keep specs and docs short and factual.
