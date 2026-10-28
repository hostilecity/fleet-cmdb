# Contributing

Work is tracked as GitHub Issues, grouped into milestones (Phase 0 to Phase 3). Issues are short stubs; the implementation details are in `docs/backlog/specs/<issue key>.md`, which is the source of truth (see `AGENTS.md`). Product requirements live in `docs/requirements.md` and decisions in `docs/decisions/`.

## Ground rules

- Work one issue per branch and pull request. Respect "blocked by" relationships.
- Code for a phase starts only after the previous phase is accepted. Decisions, mockups, and design notes may happen earlier.
- Do not build anything listed as out of scope, and do not add arbitrary remote command execution or over-the-air firmware or OS updating. Agent updates go only through the signed channel in `docs/decisions/0018-signed-agent-updates.md`.
- Never commit secrets or real fleet details (hostnames, addresses, keys, certificates). Use example values.
- Dashboard work starts from approved mockups in `docs/mockups/`.

## Branches, commits, and pull requests

- Branch names: `<issue-number>-short-slug`, for example `42-liveness-job`.
- Commit and pull request titles cite the requirement IDs they implement:
  `FR-1.4: evaluate liveness every minute`, `NFR-1: add content security policy`.
- Use the pull request template. Its **delivery note** (built, tested, acceptance criteria covered, decisions used, left incomplete) is required, and the phase acceptance issue (`P1-ACCEPT` and so on) gets a consolidated delivery note when the phase is accepted. Link the issue with `Closes #N` so merging closes it; use `Refs #N` only when more PRs for that issue will follow.
- Squash merge. Keep `main` green.

## Running things

Server (`cmdb/`): see `cmdb/README.md`. The short version:

```sh
cd cmdb
bin/setup   # install gems, prepare the database
bin/ci      # tests, rubocop, brakeman, bundler-audit
bin/dev     # run the app and job worker
```

Agent (`agent/`): `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`. See `agent/README.md`.

Use Ruby 3.4.x through chruby (the macOS system Ruby, 2.6, will not work) and PostgreSQL from Homebrew.

## Decisions

To change a decided question, copy `docs/decisions/0000-template.md`, write a new ADR that supersedes the old one, and open a pull request. Do not edit an accepted ADR to reverse it.

## Security

Report vulnerabilities privately (see `SECURITY.md`).
