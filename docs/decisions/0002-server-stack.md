# ADR 0002: Server stack baseline

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-02
- Requirements: `docs/requirements.md`, section 10

## Context

The requirements named Rails and a relational database but no versions, job backend, UI approach, or test framework.

## Decision

Ruby 3.4.10 and Rails 8.1 on PostgreSQL, with Solid Queue, Solid Cache and Solid Cable, Hotwire (Turbo and Stimulus) with importmap and Propshaft, RSpec with FactoryBot, rubocop-rails-omakase, brakeman, and bundler-audit. Deployed as Docker. This matches the owner's `homealert` project.

## Consequences

- `.ruby-version` pins 3.4.10; the macOS system Ruby (2.6) must not be used.
- PostgreSQL gives `jsonb` for snapshots and row locking for atomic task claims in Phase 3.
