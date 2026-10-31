# P0-SERVER-CI: CI for the Rails server

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- GitHub Actions workflow that runs on pull requests and on pushes to `main`: set up Ruby from `.ruby-version`, start PostgreSQL, run `bin/ci` (rspec, rubocop, brakeman, bundler-audit).
- Failures are diagnosable without the job log (#69): each failing RSpec example (location, error, seed), each error outside an example, and each failed `bin/ci` step becomes a GitHub error annotation, readable through the checks API. The `bin/ci` log and RSpec's JSON results are kept as a workflow artifact.
- Path filtering so agent-only changes do not run the server workflow (and vice versa), without leaving required checks permanently pending.
- Dependabot configuration for bundler and GitHub Actions.
- After the first green run: enable branch protection on `main` requiring this check ([DEC-09](../../decisions/0009-repository.md)).

## Acceptance criteria

- [ ] A PR touching `cmdb/` runs the workflow and reports status
- [ ] A deliberately failing spec fails the check (verified once, then reverted)
