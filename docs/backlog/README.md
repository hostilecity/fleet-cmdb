# Backlog

Source for the GitHub issues that track the Fleet CMDB build, designed to be cheap to read: **issues are short stubs, and the files in this repository are the source of truth for implementation details.**

| Path | Purpose |
|---|---|
| `issues.yml` | The 45 issues: key, title, milestone, labels, covered requirement IDs, one-sentence goal, 2 or 3 acceptance criteria, blockers |
| `specs/<key>.md` | One file per issue with the implementation details (scope, constraints, edge cases, test notes). This is what agents read |
| `config.yml` | Labels, milestones, and phase gates |
| `import.rb` | Validates the sources and creates the GitHub issues |
| `review-notes.md` | What the requirements review found (R-01 to R-37) |
| `_original-requirements.md` | The requirements draft as received, for diffing |

Decisions are not issues: all 19 are decided and recorded as ADRs in `docs/decisions/`. There are no epic issues either; each milestone shows phase progress and its exit criteria are the `AC-*` items in `docs/requirements.md`. SETUP-01 and SETUP-02 are done.

## What a GitHub issue looks like

```
**Goal:** One sentence.

**Covers:** FR-1.2, AC-1.1

**Done when**
- [ ] Acceptance criterion
- [ ] Acceptance criterion

**Details:** docs/backlog/specs/p1-agent-report.md (link)
**Blocked by:** #12, #7
```

Nothing else is copied into GitHub, so there is nothing to keep in sync: change the spec file and the issue stays correct. If an issue and its spec ever disagree, the spec wins. Agents follow `AGENTS.md`: read the spec, work from the issue, and reference it in pull requests.

## Issues by milestone

| Milestone | Issues |
|---|---|
| Phase 0 — Scaffolding | 3: agent crate and CI, server CI, API contract workspace |
| Phase 1 — CMDB & inventory | 21: server (hosts, access, API/enrollment, onboarding, heartbeat, inventory, operability, releases, rollouts), dashboard (3: fleet, actions, audit log), agent (core, install, collectors, reporting, packaging, updater), deployment, verification, acceptance |
| Phase 2 — Config, CIS & vulnerabilities | 10 |
| Phase 3 — Remote tasks | 11 |

Run `ruby docs/backlog/import.rb plan` for the full list in creation order with blockers.

**Phase gates.** Every Phase 2 issue with no blocker inside Phase 2 is blocked by `P1-ACCEPT`, and likewise Phase 3 by `P2-ACCEPT`, so a phase's code cannot start before the previous phase is accepted. Blockers are shown only when direct (a blocker already implied through another blocker is omitted).

**Traceability.** `check` fails if any `FR-*`, `NFR-*`, or `AC-*` ID in `docs/requirements.md` is not covered by some issue, and if any `DEC-*` lacks an ADR. Currently 50 of 50 covered.

## Commands

All stdlib Ruby; tested on the macOS system Ruby (2.6) and Ruby 3.4.

```sh
ruby docs/backlog/import.rb check    # validate everything; offline
ruby docs/backlog/import.rb plan     # list the issues and a sample body; offline
ruby docs/backlog/import.rb apply    # create on GitHub in the current repo; no prompt
```

`apply` always targets the current project's repository (as resolved by `gh`). Options: `--skip-links` (no blocked-by relationships), `--refresh` (rewrite title and body of existing issues from the sources).

What `check` validates: `issues.yml` parses; keys are unique; milestones and labels exist; every `covers` ID exists in the requirements; each issue has a one-sentence goal ending in a period and 2 or 3 acceptance criteria; every spec file exists, starts with its key, and has no unresolved placeholders; every relative link in a spec resolves; no orphan specs; no dependency cycles or blockers in a later milestone; every FR/NFR/AC covered; every DEC has an ADR.

What `apply` does: creates labels and milestones, then issues in dependency order (blockers first, so each body already names its blockers by number), then "blocked by" relationships. About 95 API calls, a few minutes with pacing.

Safety properties:

- It never closes or deletes anything and never edits an issue that lacks its marker comment (`<!-- backlog-key: KEY -->`).
- Existing issues are skipped, so it is resumable and a re-run on a complete import makes zero writes. Edits made on GitHub are preserved unless you pass `--refresh`.
- It needs `gh` authenticated with the `repo` scope.

**Before running `apply`:** push `docs/backlog/specs/` to the default branch, or the links in the issues will 404 (they use `blob/HEAD/...`, so no branch name is involved). The repository is public, so the issues will be public.

### How it was tested

`check` and `plan` on Ruby 2.6 and 3.4. `apply` against a fake `gh` that emulates the endpoints used: a full run, a run killed partway and resumed, a re-run with zero writes, and `--refresh`. It has **not** been run against live GitHub; the dependency endpoint was checked against GitHub's published API description, not exercised. 

## Changing the backlog

- Change implementation details: edit `specs/<key>.md`. Nothing on GitHub needs to change.
- Change a goal, acceptance criterion, requirement coverage, or blocker: edit `issues.yml`, run `check`, then edit the GitHub issue (or `apply --refresh`).
- Add an issue: add an `issues.yml` entry and `specs/<key>.md`, run `check`, then `apply` (existing issues are skipped).
- `specs/`, `issues.yml`, and `config.yml` are permanent: they are the implementation source of truth. Once the import is done, `import.rb`, `review-notes.md`, and `_original-requirements.md` can be deleted if you want.
