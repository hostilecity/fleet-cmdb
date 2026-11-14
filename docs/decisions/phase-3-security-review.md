# Phase 3 security review: no arbitrary shell, adversarial and crash tests

- Status: **Done** for [P3-X01, P3-X02, P3-X03](../backlog/specs/p3-security.md) (issue #38). This is the written review note AC-3.2 asks for. Attach it to the Phase 3 delivery note.
- Reviewed: `main` at `6aae4e3` (every Phase 3 build pull request merged: #153, #154, #164 to #172), plus the tests and the one hardening fix added with this note.
- Companion: the [threat model](phase-3-threat-model.md), finalised in the same pull request. Its rows cite the tests below.
- Requirements: `FR-3.1`, `FR-3.3`, `NFR-1`, `AC-3.1`, `AC-3.2`, `AC-3.3`, `AC-3.7`

This note decides nothing. It records what was checked, how, and what was found. Paths are cited as `path:line` against the reviewed code.

## 1. Result

**No path was found from any input to an arbitrary command, on the server or on the agent.**

- No server route or parameter that reaches a task accepts a command, script, path, executable name, option, or environment variable. The one task-creating route takes a type id looked up in the catalog, parameters checked against a closed schema, and a host selection. Everything else in the request is refused, not ignored.
- The poll payload carries five fields: id, type, parameters, deadline, and catalog version.
- Every process the agent starts has an absolute program path fixed in its code, a fixed argument vector, no shell, and a cleared environment. A value that comes from the server is only ever one argument, after `--` or as a fixed property, and only after a validator built it. Section 4 lists every spawn.
- The agent never loads task definitions at run time. A type it has no code for is `not_supported`, whatever the catalog says.

One small hardening fix was made (F-8 below). Nothing found needed a follow-up issue. Section 9 lists what is left for the owner to decide.

## 2. Method

1. Listed every route with `bin/rails routes`. For each route that can create, change, or deliver a task, read the controller, the service it calls, and the permitted parameters (section 3).
2. Listed every process spawn in non-test agent code with `grep -rn "Command::new\|process::Command\|\.spawn()"`. For each, traced every argument back to its source (section 4).
3. Searched both codebases for shells and string-built or dynamic commands (section 5).
4. Checked which CI jobs run these checks, and on which pull requests (section 6).
5. Mapped every FR-3.1 and FR-3.3 bullet to code and a test (section 7).
6. Listed the adversarial and crash tests. Added the ones the spec asks for that did not exist yet, and checked first that each new test can fail (section 8).
7. Ran the dependency audits (section 6).

## 3. Inputs, and what each can make an agent run

Each input below is assumed hostile. "Guards" are the checks in its way, in order. Agent-side guards hold even when every server-side guard has failed.

| Input | Path to an agent | Guards | Proven by |
|---|---|---|---|
| **Dashboard operator**, or a forged dashboard POST | `POST /tasks` (`task_creations#create`) → `TaskBatches.create!` → `tasks` rows | CSRF token (Rails); TOTP step-up `create_task` (`cmdb/app/controllers/task_creations_controller.rb:24`); a signed confirmation token for this request and these hosts, under 30 minutes old; only `type`, `parameters`, `target`, `confirm_host_count` accepted, any other key refused (`cmdb/app/services/task_batches.rb:38`, `:123`); type looked up in the catalog, never built from the request; parameters through the closed schema (`cmdb/lib/task_catalog.rb:83`) and `TaskPolicy.refusal` (`cmdb/app/models/task_policy.rb:36`); 25-host cap and typed count | `spec/requests/task_creations_spec.rb` "gives a forged POST the same validation as the form"; `spec/services/task_batches_spec.rb` "refuses a command-like field anywhere in the request"; `spec/requests/task_adversarial_spec.rb` (every task route refused without a step-up, with no factor, and without a CSRF token) |
| Operator changing the **server allowlist or limits** | `task_settings#add_service`, `#remove_service`, `#update_limits` | Step-up `change_task_settings` (`cmdb/app/controllers/task_settings_controller.rb:8`); service name `^[a-z0-9][a-z0-9_.-]{0,55}\.service$` in the model (`cmdb/app/models/task_allowed_service.rb:7`) and a database check constraint; protected names refused; limits are bounded integers | `spec/requests/task_settings_spec.rb`; `spec/models/task_settings_spec.rb`; `spec/requests/task_adversarial_spec.rb` |
| **Database writer** (bypasses the application, its step-up, and its audit) | `INSERT INTO tasks` | `tasks_guard` trigger: a row starts `queued`, and its type, parameters, host, batch, expiry, and timeout never change (`cmdb/db/functions/tasks_guard_v02.sql:13`, `:31`); check constraints on size, state, and timeout; **claim-time re-validation**: every poll and every start checks the row against the current catalog and `TaskPolicy` (`cmdb/app/services/agent_tasks.rb:151`, `cmdb/app/models/task.rb:100`) and refuses it, with the system as actor; then every agent-side guard below | `spec/requests/task_adversarial_spec.rb` "refuses every hostile row when it would be claimed" (21 hostile rows inserted with SQL); `spec/models/task_spec.rb` "the tasks_guard trigger, for code paths that skip the model" |
| **Compromised server** (sends anything it likes on the poll) | `POST /api/v1/tasks/poll` response | Agent: poll body read into five typed fields; id must be a lower-case UUID; type must match the type-id form; parameters must be an object; timeout 1 to 86400 (`agent/src/tasks/wire.rs:192`); other fields have nowhere to go. Then: type in the **embedded** catalog and implemented in this binary; type enabled in the local config; parameters parsed into a typed struct with `deny_unknown_fields` (`agent/src/tasks/executor/mod.rs:217`); for `restart_service`, the strict pattern, the local allowlist, the protected list, and alias resolution; ledger refuses an id it has seen; nothing runs until the server accepts `start`; timeout = min(server, catalog) (`agent/src/tasks/executor/mod.rs:477`) | `agent/src/tasks/poller/tests.rs` `a_canary_proves_refused_tasks_run_nothing_and_an_accepted_one_runs`, `every_local_refusal_is_reported_with_its_reason_and_nothing_starts`; `agent/src/tasks/wire.rs` `a_hostile_servers_extra_fields_never_reach_the_task_and_bad_type_ids_are_not_tasks`; `agent/src/tasks/restart_service.rs` `refused_names_run_nothing`, `fuzzed_service_names_are_refused_by_the_pattern_and_never_reach_systemctl`; `agent/src/tasks/executor/tests.rs` `parameters_are_checked_strictly_and_refused_with_nothing_run`, `the_timeout_is_the_lower_of_the_servers_and_the_catalogs` |
| Compromised server, **through the update directive** | Heartbeat `agent_update`: a version and three URLs | The documented exception (threat model section 8): the version must be strict SemVer (`agent/src/update/layout.rs:96`) and not older than the running one; the manifest must carry a minisign signature by an embedded key; the binary must match its SHA-256. URLs are only fetched. The programs run (`systemd-run`, `systemctl`, the staged binary's `self-test`) are fixed (`agent/src/update/mod.rs:91`, `agent/src/update/stage.rs:288`) | `agent/src/release/tests.rs`; `agent/src/update/tests.rs`; `scripts/update-smoke.sh` in CI (tampered, unsigned, wrongly signed, and older releases refused) |
| Compromised server, **through the config manifest** (Phase 2) | `service:<unit>` and `file:<path>` facts | Unit names must pass `valid_unit` (`agent/src/facts/systemd.rs:49`) before `systemctl show --`; now also checked inside `show` itself (F-8). Paths must be canonical (`agent/src/facts/files.rs:30`) and are only `stat`ed, never opened or run | `agent/src/facts/systemd.rs` `unit_names_are_checked_before_they_reach_a_command`, `show_refuses_a_name_that_is_not_a_unit_name_and_runs_nothing`; `agent/src/facts/tests.rs` `a_reader_cannot_read_a_secret_file_even_if_it_asks` |
| Compromised server, **through report requests** | Heartbeat `report_request.types` | An enum of `config`, `inventory`, `packages` (`cmdb/app/models/report_request.rb:7`); the agent only sends reports | `spec/requests/host_actions_spec.rb`; heartbeat contract tests |
| **Forged agent API request** (a compromised VM, or the LAN with a stolen credential) | `POST /api/v1/tasks/*` | No agent endpoint creates a task. The host is always the credential's host; another host's task is the same 404 as an unknown one (`cmdb/app/controllers/api/v1/tasks_controller.rb:68`); body size limit before parsing, JSON object only, nesting at most 16, no compression, schema validation (`cmdb/app/controllers/api/v1/base_controller.rb:75`, `:100`); unknown fields ignored and logged by path only; output stored as inert, sanitised text | `spec/requests/api/tasks_spec.rb` (each endpoint); `spec/requests/task_adversarial_spec.rb` "hostile bodies and ids on the agent task endpoints" |
| **Catalog change** (a pull request) | `docs/api/tasks/task-catalog.json`, compiled into the agent and loaded by the server | Server lint at boot and in CI: closed schemas, no command-like parameter names, every string bounded with an enum or a strict pattern that cannot match a space, slash, or shell character (`cmdb/lib/task_catalog.rb:147`, `:238`); agent compiles the same bytes in and checks it (`agent/src/tasks/catalog.rs:90`); a catalog type without agent code is `not_supported`; reaching agents needs a signed release approved in the protected `release` environment (ADR 0018) | `spec/lib/task_catalog_spec.rb`; `agent/tests/contract.rs` `the_agent_compiles_in_the_shared_task_catalog`; `agent/src/tasks/catalog.rs` `the_embedded_catalog_is_the_shared_file_byte_for_byte`; `agent/src/tasks/executor/tests.rs` `the_production_registry_implements_only_the_built_types` |
| **Agent config** (`/etc/fleet-agent/config.toml`, root, `0600`) | `[tasks]`: enabled types, allowed services, limits | Writable only by root on the VM, who needs no agent to run commands. Still: unknown types, bad names, and any other mistake enable nothing (`agent/src/tasks/settings.rs:68`); protected names are refused even when listed (`agent/src/tasks/settings.rs:262`); no setting names a program, path, or argument | `agent/src/tasks/settings.rs` `unknown_types_fail_safe_with_a_message_naming_the_choices`, `every_other_mistake_fails_safe_too`, `protected_services_are_refused_even_when_listed` |

## 4. Every process the agent starts

Non-test code only. `#[cfg(test)]` helpers that run `/bin/sh` (for example `agent/src/facts/host.rs`'s `sh()`) are absent from the release binary; `scripts/check-task-spawns.sh` and `scripts/check-no-fault-hooks.sh` check that test code stays out.

| Where | Program (absolute, fixed in code) | Arguments | Any non-constant argument, and its guard |
|---|---|---|---|
| `agent/src/tasks/executor/spawn.rs:207`, the only spawn for tasks | `Program.path: &'static str` (`spawn.rs:73`) | `&'static [&'static str]`, then `--`, then at most one `ValidatedArg` (`spawn.rs:161`) | `ValidatedArg::service_unit` (`spawn.rs:94`) is the only constructor: the catalog pattern, after the local allowlist and protected checks. `env_clear` plus a fixed set (`spawn.rs:210`) |
| Task steps: `restart_service` | `/usr/bin/systemctl` (`agent/src/tasks/restart_service.rs:224`) | `restart`, `is-active`, `status --no-pager --full --lines=20` | The service, as a `ValidatedArg` after `--` |
| Task steps: `apply_package_updates` | `/usr/bin/apt-get` (`agent/src/tasks/apply_updates/apt.rs:33`), `needrestart` | Fixed vectors in `apt.rs` | None. The type takes no parameters |
| Task steps: `refresh_reports` | None: it asks the report loop | — | None. Any parameter is `invalid_params` |
| Transient units for package-manager steps | `/usr/bin/systemd-run`, `systemctl`, `journalctl` (`agent/src/tasks/executor/unit.rs:33`) | Fixed properties | `Generated` values only (`spawn.rs:111`): a unit name from a task id that passed `is_task_id` (`spawn.rs:117`), a number of seconds (`spawn.rs:123`), or 32 hex digits (`spawn.rs:128`) |
| Fact collectors (`agent/src/facts/host.rs:305`) | First existing of a `&'static` list: `systemctl`, `sshd -T`, `apt-config dump`, `dpkg-query` (`facts/systemd.rs:27`, `facts/sshd.rs:84`, `facts/updates.rs:68`, `packages.rs:175`) | Fixed | Unit names from the config manifest, after `--`, checked by `valid_unit` (F-8 makes that check unconditional) |
| Update self-test (`agent/src/update/stage.rs:288`) | The staged binary, `<lib>/versions/<version>/fleet-agent` | `self-test --config <agent's own config path>` | The version: strict SemVer, then signature and hash (section 3) |
| Update supervisor (`agent/src/update/mod.rs:91`) | `systemd-run` | Fixed, then `--`, the running binary's own path, `update-supervise --config <path>` | None from the server |
| Supervisor and installer `systemctl` (`agent/src/install/systemd.rs:111`, `agent/src/update/supervise.rs`) | `systemctl` | Constants (`UNIT_NAME`, `SUPERVISOR_UNIT`) | None |

No spawn passes a value in an executable or option position. No spawn uses a shell.

## 5. Searches

| Codebase | Searched for | Found | Verdict |
|---|---|---|---|
| `agent/src` (non-test) | `sh -c`, `/bin/sh`, `bash`, `"-c"`, `system(`, `popen`, `libc::exec*`, `Command::new` with a non-literal, `format!` into an argument list | `Command::new` with a variable only in `spawn.rs:207` (a `&'static str`), `facts/host.rs:305` (from a `&'static` list), `stage.rs:297` (the verified staged binary), `install/systemd.rs:113` (a fixed path). `format!` in `spawn.rs` only in `Generated`'s constructors | Safe. The task module part is enforced in CI by `scripts/check-task-spawns.sh`, with a self-test that proves it catches bypasses |
| `cmdb/app`, `cmdb/lib`, `cmdb/config` | `system(`, backticks, `%x`, `Open3`, `IO.popen`, `Process.spawn`, `exec(`, `eval`, `instance_eval`, `class_eval`, `constantize`, `send(`, `public_send(`, `ERB.new`, `render inline` | No shell or eval. `public_send` only with names from code: `Rollouts.public_send(method)` (actions name the method), `AgentTasks` events from the `EVENTS` constant, `TaskSettings` fields from `LIMITS`. Backticks only in message strings | Safe |
| `cmdb/bin`, `cmdb/lib/tasks` | The same | `bin/setup` and `bin/docker-entrypoint` run commands; they are deploy-time scripts with no request input. Rake tasks run no shell | Not reachable from a request |
| Dashboard live updates | Turbo and Action Cable channels | No custom channels. Broadcasts are `broadcast_refresh_to` only: no content, and a refresh re-renders the escaped page | Safe |

## 6. CI and dependencies

| Check | Where | Runs on |
|---|---|---|
| Catalog lint and loading | `spec/lib/task_catalog_spec.rb`; `config/initializers/task_catalog.rb` (boot) | Server CI: every PR touching `cmdb/**` or `docs/api/**` |
| Catalog contract: agent and server read the same bytes | `agent/tests/contract.rs`, `agent/src/tasks/catalog.rs` tests | Agent CI: every PR touching `agent/**` or `docs/api/**` |
| No shell in the task module | `scripts/check-task-spawns.sh` and its `--self-test` | Agent CI, "fmt, clippy, test" |
| No fault-injection hooks in the release binary (new) | `scripts/check-no-fault-hooks.sh` | Agent CI, sandbox job |
| P3-X02 and P3-X03 tests | `cargo test`; `bundle exec rspec` | Both CIs |
| Task privileges under the real unit | `scripts/task-privilege-smoke.sh` | Agent CI, sandbox job |
| Dependency audit | `cargo audit --deny warnings`; `bin/bundler-audit`, `bin/importmap audit`, Brakeman | Agent CI "Dependency audit"; Server CI `bin/ci` |

Dependency audit results: `bundler-audit` found no vulnerabilities (run for this review, 2026-11-13). `cargo audit --deny warnings` passed on `main` at `6aae4e3` (2026-11-11) and runs again on this pull request. Dependabot is on for both. Phase 3 added one dependency: the `rqrcode_core` gem, which draws the TOTP enrolment QR code on the server (#165). The agent gained no crate in Phase 3.

**Finding F-9 (repository setting, not code):** branch protection on `main` requires only the **Server CI** check. **Agent CI** runs on every pull request, but a failing Agent CI does not block a merge, so the catalog contract test, the no-shell check, and the fault-hook check are advisory today. `agent-ci.yml` itself says branch protection should require it. This is the owner's setting to change (Q13).

## 7. FR-3.1 and FR-3.3, bullet by bullet

| Requirement bullet | Code | Test |
|---|---|---|
| FR-3.1: fixed catalog in agent code, mirrored on the server, checked against one shared file | `agent/src/tasks/catalog.rs:90` (`include_str!`); `cmdb/lib/task_catalog.rb` | `the_embedded_catalog_is_the_shared_file_byte_for_byte`; `agent/tests/contract.rs`; `spec/lib/task_catalog_spec.rb` ".load" |
| FR-3.1: the server never sends a command line, shell string, script, or executable name | `TaskBatches::REQUEST_KEYS`; `AgentTasks.delivery` (`cmdb/app/services/agent_tasks.rb:89`); `task-poll.response` schema | `spec/requests/api/tasks_spec.rb` "delivers only its id, type, parameters, deadline, and catalog version"; `spec/services/task_batches_spec.rb` "refuses a command-like field"; `task_adversarial_spec.rb` |
| FR-3.1: the agent maps the type to its own implementation; unknown type or invalid parameter is refused and reported | `agent/src/tasks/poller.rs:710`; `executor::parse` | `every_local_refusal_is_reported_with_its_reason_and_nothing_starts`; `a_canary_proves_refused_tasks_run_nothing_and_an_accepted_one_runs`; `parameters_are_checked_strictly_and_refused_with_nothing_run` |
| FR-3.1: a new type needs a new agent release and a server catalog entry; never a dashboard-only change | Catalog compiled in; `TaskCatalog::Catalog` frozen; registry lists built types only | `the_production_registry_implements_only_the_built_types`; `spec/lib/task_catalog_spec.rb` "is frozen, so nothing can add an entry at runtime" |
| FR-3.1: the agent reports types and catalog version; the server offers only supported types | `agent/src/tasks/mod.rs` `Capabilities`; `Host#task_exclusion_reason` | `capabilities_report_the_catalog_version_and_the_local_choice`; `task_batches_spec.rb` "excludes hosts that ... do not support or enable the type" |
| FR-3.1: initial catalog of three types | `docs/api/tasks/task-catalog.json` | `the_embedded_catalog_parses_and_has_the_initial_types` |
| FR-3.1: both allowlists must permit a restart; protected services always refused | `TaskPolicy` (`cmdb/app/models/task_policy.rb:17`); `agent/src/tasks/settings.rs:262`; `agent/src/tasks/restart_service.rs` | `refused_names_run_nothing` (AC-3.9); `protected_services_are_refused_even_when_listed`; `task_batches_spec.rb` "refuses what the server's policy does not allow"; `spec/requests/api/tasks_spec.rb` "refuses at claim time a restart whose only allowlist entry is for a tag the host no longer has" |
| FR-3.3: each type declares its privilege; minimum privilege; per-type statement | `privilege` in the catalog; `docs/operations/agent-task-privileges.md` | `a_program_needing_more_than_the_catalog_privilege_never_runs`; `scripts/task-privilege-smoke.sh` |
| FR-3.3: clean fixed environment and working directory; non-interactive set by the agent | `spawn.rs:210` | `the_environment_is_exactly_the_fixed_set_and_nothing_else_leaks_in`; `a_task_runs_in_slash_with_standard_input_closed_and_its_own_process_group` |
| FR-3.3: one task at a time | `AgentTasks.poll!` (one claimed or running task per host); the poller's single slot | `spec/requests/api/tasks_spec.rb` "holds one task at a time", "never delivers a started task again, nor anything else while it runs"; `a_task_left_running_in_its_unit_is_waited_for_after_a_restart_and_then_reported` |
| FR-3.3: shutdown mid-task is reported as interrupted on the next start | `agent/src/tasks/poller.rs:404` | `killed_after_started_reports_interrupted_and_never_runs_it`; `shutdown_stops_an_interruptible_task_and_reports_it_interrupted`; the kill-point matrix |
| FR-3.3: output is untrusted text: truncated, stored, rendered escaped; no secrets in environment or arguments | `TaskOutput` (`cmdb/app/models/task_output.rb:29`); `<pre>` with ERB escaping; executor output bounds | `spec/models/task_output_spec.rb`; `spec/requests/api/tasks_spec.rb` "truncates oversize output", "stores output with markup and control characters as inert text"; `hostile_input_spec.rb` "escapes the task list, a task's page, its output..."; `gigabytes_of_output_are_bounded_and_marked_truncated`; privilege smoke "cannot read the agent's credential" |

## 8. Adversarial and crash tests (P3-X02, P3-X03)

Existing tests were reused. New tests are marked **new**. Each new test was first checked to fail when the guard it covers is removed.

### P3-X02: hostile traffic

| Case | Test |
|---|---|
| Unknown type, extra fields, wrong types, oversize, command-like names, via the dashboard | `task_creations_spec.rb` "gives a forged POST the same validation as the form"; `task_batches_spec.rb` "refused requests create nothing (AC-3.2)" |
| Every task-changing dashboard route enumerated from the router: refused without a step-up, without an enrolled factor, and without a CSRF token, with nothing changed | **new** `task_adversarial_spec.rb` "the task-changing dashboard routes" |
| A step-up in one session does not carry to another; replayed and brute-forced codes | `spec/requests/second_factor_required_spec.rb` "does the action with a right code, then for 5 minutes without one, in this session only"; `spec/services/second_factors_spec.rb` "accepts a code once: the same code again ... is refused as reused", "locks after 5 wrong codes in 15 minutes per operator" |
| Hostile tasks written straight into the database: unknown types, command fields, `; reboot`, `$(...)`, backticks, `../`, option-like names, bidi characters, newlines, globs, other unit types, protected names in other case, unlisted services | **new** `task_adversarial_spec.rb` "tasks written straight into the database"; trigger tests in `spec/models/task_spec.rb` |
| Malformed, oversize, deep, compressed, non-JSON bodies, injection strings in declared fields, command-like unknown fields, odd ids, on every agent task endpoint | **new** `task_adversarial_spec.rb` "hostile bodies and ids"; `spec/requests/api/tasks_spec.rb` "refuses a body that fails the schema", "takes a body up to 1 MiB and refuses a larger one" |
| Another host's task, on every endpoint | `spec/requests/api/tasks_spec.rb` "never delivers another host's task", "answers 404 for another host's task" (start, progress, result) |
| Replayed ids, duplicate delivery | `duplicate_delivery_of_one_id_runs_it_once`; **new** replays inside the kill-point matrix |
| A hostile server's payload: extra fields, bad ids, types, parameters, timeouts | `every_poll_example_reads_as_the_contract_says`; **new** `a_hostile_servers_extra_fields_never_reach_the_task_and_bad_type_ids_are_not_tasks` |
| Canary: refused tasks run nothing | `a_canary_proves_refused_tasks_run_nothing_and_an_accepted_one_runs` (real registry and spawn path); the fake systemctl's call log in `refused_names_run_nothing` |
| Path traversal and unit aliasing in service names | `refused_names_run_nothing` (aliases, chains, reverse aliases, templates, masked units) |
| Terminal escapes, bidi, invalid UTF-8, markup in output | `spec/models/task_output_spec.rb`; `spec/requests/api/tasks_spec.rb` "stores output with markup and control characters as inert text"; `hostile_input_spec.rb`; `spec/requests/tasks_spec.rb` the download is an attachment with `nosniff` (**new** assertion) |
| Fuzz of the validators | **new** agent `fuzzed_service_names_are_refused_by_the_pattern_and_never_reach_systemctl` (5,000 names); **new** server "a fuzz of the server's parameter validator" (3,000 names and keys) |
| Concurrent claims | `spec/services/agent_tasks_concurrency_spec.rb` "claims exactly one task" |

### P3-X03: crashes, restarts, idempotency

| Case | Test |
|---|---|
| Agent killed after `received`, after `started`, after the server's acceptance, mid-run, after `finished` | `killed_after_received_reports_not_run_and_never_runs_it`, `killed_after_started_reports_interrupted_and_never_runs_it`, `killed_mid_run_reports_interrupted_and_never_runs_it_again`, `killed_after_finished_sends_the_stored_result_unchanged` |
| **At least 100 randomised kill-point runs** with no double run (P3-X03 AC) | **new** `no_kill_point_in_a_hundred_and_twenty_randomised_runs_runs_a_task_twice`: 120 seeded runs, each with 1 to 4 tasks and 1 to 6 lives, killed at a random point (or not), with lost poll replies (a kill mid-poll), failed polls, starts and results, and replays of earlier ids. The ledger has three independent guards against a second run (known id at `ledger.rs:515`; a record never moves a task back, `ledger.rs:806`; `executing` only once, `ledger.rs:583`): the matrix reports a double run on the first seed only when all three are removed, which is how it was checked |
| A task still running in its transient unit when the agent restarts | `a_task_left_running_in_its_unit_is_waited_for_after_a_restart_and_then_reported`; `recovery_waits_for_a_running_unit_and_then_reports_what_it_did`; `scripts/vm-test.sh` "Agent restarted during the upgrade (L8)" |
| Damaged ledger, failed appends (disk full) | `a_damaged_ledger_holds_every_task`; `agent/src/tasks/ledger/tests.rs` |
| Interruption reported on the next start | The kill-point tests above; `shutdown_stops_an_interruptible_task_and_reports_it_interrupted` |
| Server: simultaneous polls | `agent_tasks_concurrency_spec.rb` "claims exactly one task" |
| Server: simultaneous starts, duplicate and conflicting results | **new** `agent_tasks_concurrency_spec.rb` "starts a claimed task once when its start arrives many times at once", "stores one result when the same result arrives many times at once", "keeps the first of two different results that arrive at once" |
| Server: repeated starts and results in sequence | `spec/requests/api/tasks_spec.rb` "is idempotent: a repeated start still says run", "accepts the same result again and changes nothing", "refuses a conflicting second result with 409" |
| Server fails mid-claim; database unavailable | **new** `task_adversarial_spec.rb` "a server that fails mid-claim": no half-made claim, the next poll claims once; a lost database answers 500 with no internals, which the agent retries (`agent/src/tasks/wire.rs` `final_or_retry`; `a_failed_poll_backs_off`, `start_is_retried_and_the_task_runs_only_once_accepted`) |
| Lease, expiry, and timeout jobs racing polls | `spec/services/task_leases_concurrency_spec.rb`; `spec/services/task_leases_spec.rb` |
| Release binary has no fault-injection code | **new** `scripts/check-no-fault-hooks.sh` in Agent CI: hook calls are behind `#[cfg(test)]`, `Cargo.toml` declares no features, the unit-test binary carries the hook marker (`agent/src/test_support.rs`), and the release binary does not |

## 9. Findings

### Fixed in this pull request

| ID | Finding | Fix |
|---|---|---|
| F-8 | `facts::systemd::show` passes unit names to `systemctl show --`. Some names come from the server's config manifest. Its own check was a `debug_assert!`, so release builds relied on every caller checking first. All callers did, and the names follow `--`, so nothing was exploitable | `show` now refuses any name that fails `valid_unit`, in every build, with nothing run (`agent/src/facts/systemd.rs:84`), with a test |
| — | The P3-X03 AC "release binary contains no fault-injection code (verified in CI)" had no CI check; the hooks were test-only by construction | `scripts/check-no-fault-hooks.sh`, run in Agent CI |
| — | Tests the spec lists that did not exist yet | Section 8, marked **new** |

### Not fixed: no code change needed, or the owner's call

| ID | Observation | Why no change | Where |
|---|---|---|---|
| F-9 | Agent CI is not a required check on `main` | Repository setting | Q13 |
| F-10 | No CODEOWNERS file (threat model S2's proposal) | With one maintainer, a required code-owner review cannot be given by anyone but the author, and GitHub does not let authors approve their own pull requests. The protected `release` environment already needs the owner's approval for anything to reach agents | Q14 |
| F-11 | Zero-width characters in task output are stored and shown invisibly (threat model O2's proposal) | Not in any spec. Bidi overrides, which can reorder text, are removed; zero-width characters can only split or join words, and the output is labelled as agent text | Q11 |
| F-12 | An operator may set a task type's expiry up to 7 days (owner decision Q33), while the agent's ledger hold after damage lasts the catalog's longest expiry plus timeout (25 hours) | The hold guards against a hostile or buggy server only: an honest server never redelivers a started task as runnable. A hostile server can mint a new id anyway (C8) | Recorded; no question |

No security finding is open. Nothing here needed a follow-up issue.

The questions for the owner are in the threat model, section 11.
