# ADR 0012: CIS rule condition format

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-12
- Requirements: `docs/requirements.md`

## Context

FR-2.2 required a condition expression but did not define one, and evaluating code on influenced data is unsafe.

## Decision

Rules are **YAML files** validated against a JSON Schema, with a closed operator set: `eq`, `ne`, `in`, `not_in`, `present`, `absent`, `gte`, `lte`, `matches` (anchored, time-limited), `mode_at_most`, and the combinators `all`, `any`, `not`. A fact reported unreadable always yields `not_readable`. A rule whose `applies_to` does not match the host yields `not_applicable`. **No code is ever evaluated.**

## Consequences

- The example and schema live in `docs/api/`; the evaluator is a pure function with table-driven tests.
