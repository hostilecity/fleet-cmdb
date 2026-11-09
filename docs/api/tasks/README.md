# Task catalog

The task types an operator may run on a VM (FR-3.1, P3-S01). The server can only ever send a task type id from this catalog and parameters that validate against that type's closed schema; it never sends a command line, shell string, script, or executable name (AC-3.2).

- **[`task-catalog.json`](task-catalog.json)** is the one definition. The server reads it at boot (`cmdb/lib/task_catalog.rb`) and the agent compiles it into its binary (P3-A01), so the two cannot drift; CI checks that both read this file. Neither side builds a task type from anything else.
- **[`task-catalog.schema.json`](task-catalog.schema.json)** is the structural half of the catalog lint (JSON Schema draft 2020-12).
- **[`examples/`](examples/)** holds catalogs the lint must accept (`valid/`) and reject (`invalid/`, named for why). `cmdb/spec/contract/task_catalog_contract_spec.rb` checks every one.

The file is JSON so that both sides read it with the parsers they already have (`serde_json` in the agent, `JSON` in the server), with no YAML parser in the agent. It must be UTF-8 and must not repeat a key.

## An entry

| Field | Meaning |
|---|---|
| `type` | Stable id (`^[a-z][a-z0-9_]{0,63}$`). Never renamed or reused |
| `name` | Plain-language name for the dashboard |
| `description` | Exactly what the task runs and changes, as the dashboard shows it before an operator creates the task |
| `since` | The `catalog_version` that added the type. An agent reporting a lower catalog version does not have it |
| `privilege` | What the task needs on the VM: `read_only`, `service_manager`, or `package_manager` (FR-3.3; the per-task privilege table is P3-A05) |
| `interruptible` | Whether a running task can be stopped safely on cancel (FR-3.2, DEC-14) |
| `enabled_by_default` | Whether an agent runs the type without a local configuration change. Only `read_only` types may be (DEC-14) |
| `timeout_seconds` | Default time a task may run, from start to result (FR-3.2) |
| `expiry_seconds` | Default time a task may wait to start, from creation; then it expires and is never delivered (AC-3.8). 24 hours for every initial type (DEC-14) |
| `parameters` | A closed JSON Schema: `{"type": "object", "additionalProperties": false, "properties": {...}, "required": [...]}` |

`catalog_version` at the top increases by one whenever a type is added or changed, and equals the highest `since`. `format_version` is 1.

The initial entries: `refresh_reports` (no parameters; reuses the DEC-13 report path), `restart_service` (one `service` parameter, a full systemd service unit name; also checked against the server and agent allowlists, DEC-15), and `apply_package_updates` (no parameters, DEC-16).

## What the lint enforces

The server runs the lint whenever it loads the file, so it does not boot with a catalog that fails, and the spec suite runs it on every example.

- **Closed schemas.** `additionalProperties` is `false`; no `patternProperties`, `default`, `$ref`, or any other keyword. At most 16 parameters per type.
- **Only three parameter types.** A `string` with a `maxLength` (at most 256) and an `enum` or a `pattern`; an `integer` with `minimum` and `maximum`; a `boolean`. No lists and no objects, so no argument vectors and no environments.
- **No free-form strings.** A pattern is anchored with `^` at the start and `$` at the end, and nowhere else. It may match only letters, digits, and `_ . @ + -`: never a space, a slash, a quote, or a shell character. No `.` wildcard outside a character class, no negated class (`[^...]`), no special group (`(?...)`), and no escape but `\.`, `\-`, `\+`, and `\d`. A range in a class stays within `A-Z`, `a-z`, or `0-9`, because a range like `[.-z]` would match `/` and `;`; write a literal `-` as `\-`, or first or last in the class. No `|` outside a group: `^ok|fine$` would anchor each alternative only at one end, so write `^(ok|fine)$`. Enum values use the same characters and fit the parameter's own length and pattern.
- **No command-like names.** A parameter name containing `command`, `cmd`, `shell`, `script`, `exec`, `eval`, `sudo`, `program`, `binary`, or `executable`, or with a word (between `_`) such as `arg`, `args`, `argv`, `option`, `flag`, `env`, `environment`, `path`, `file`, `dir`, `url`, or `uri`, is refused.
- **Consistent versions and safe defaults.** Type ids are unique, `catalog_version` equals the highest `since`, and only `read_only` types are `enabled_by_default`.

The server validates a task's parameters against its entry when the task is created and again when it is claimed: extra fields, missing required ones, wrong types (a number with a fraction is not an integer), oversize values, and values outside an enum or pattern are refused, and the reasons never repeat the value sent.

## Adding or changing a task type

A task type is never a dashboard-only or server-only change (FR-3.1). It needs a catalog change, a new agent release, and a server release, in this order:

1. **Decide it.** A new type, or a change to what one runs, needs an owner decision (an ADR, as DEC-15 and DEC-16 are) that says exactly what it runs, what it may change, its privilege, whether it is interruptible, and its timeout.
2. **Edit `task-catalog.json`.** Add the entry with `since` set to the new `catalog_version`, one more than before. Never remove, rename, or retype an existing type or parameter, and never widen a pattern or enum in place: add a new type instead, so an agent built against the older catalog never receives a parameter it would read differently. Run the lint: `NO_COVERAGE=1 bundle exec rspec spec/contract/task_catalog_contract_spec.rb` in `cmdb/`.
3. **Implement it in the agent** (P3-A03): a fixed implementation with typed parameters, no shell, a fixed argument vector, a clean environment, and the privilege the entry declares; then add it to the privilege table (P3-A05). Release the agent (`docs/releases.md`).
4. **Release the server** with the same file. The server offers the type only to hosts whose agent reports it as supported and enabled, so older agents are never sent it.
5. **Tick the task item in the pull request checklist** (`.github/pull_request_template.md`).
