# P3-AGENT-EXEC: Agent task executor and privilege model

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-A03: Agent: task executor framework and execution safety

### Scope

- A fixed registry mapping task type id to a Rust implementation. An unknown type, or any parameter failing strict validation (typed structs with `deny_unknown_fields` and explicit range and pattern checks), results in a `refused` report with a reason and **no execution**.
- Child processes are started only from an argument vector with an absolute executable path and fixed arguments. No shell (`sh -c`) anywhere. Parameters can select among implemented behaviours or fill a validated, quoted-by-construction argument position, never become an executable or an option.
- Clean environment (`env_clear`, then only fixed variables such as `PATH`, `LANG=C`, `DEBIAN_FRONTEND=noninteractive`), fixed working directory, standard input closed.
- Each child runs in its own process group so timeout kills the whole tree: graceful signal, grace period, then kill. The agent terminates its own over-running task and reports `timed_out`.
- Timeout is the smaller of the server's deadline and the catalog maximum.
- Output capture is bounded in memory and truncated with a marker to the server-defined limit.
- One task at a time: a second claimed task waits.
- Shutdown during a task: record the interruption (the ledger from [P3-A02](p3-agent-ledger.md)) so the next start reports it.
- No debug or fault-injection hooks compiled into release builds (see [P3-X03](p3-security.md) for how tests get them).

### Acceptance criteria

- [ ] AC-3.1 (agent half): unknown types and invalid parameters are refused, and a canary check proves nothing was executed
- [ ] A static check (CI grep or clippy configuration) fails if `Command::new("sh")`, `-c`, or string-built command lines appear in the task module
- [ ] AC-3.5 (agent half): a task exceeding its timeout is terminated including its children, and `timed_out` is reported
- [ ] Output from a task producing gigabytes is bounded and marked truncated
- [ ] The environment inside a task is exactly the fixed set

## P3-A05: Agent privilege implementation and per-task privilege table

### Scope

- Implement the [DEC-03](../../decisions/0003-agent-privilege.md) model for tasks: for the default (root with hardened unit), review every `systemd` sandboxing option against what each task needs and relax only what is required, writing down why. Package updates must write to places such as `/usr`, `/etc`, `/boot`, and `/var`; restarting services needs access to the service manager; read-only collection needs none of that.
- For a sudo-based model, the `sudoers` drop-in with exact fixed commands and the install steps.
- A **per-task-type privilege table** (task type, privilege used, why it is the minimum that works) in `docs/` and in the delivery note.
- Where practical, drop capabilities or privileges for task types that do not need them.

### Acceptance criteria

- [ ] Each task type works under the final unit file on the test VM
- [ ] The privilege table exists and is reviewed against the real unit and commands
- [ ] `systemd-analyze security` output before and after is recorded

## As built (#35)

Code: `agent/src/tasks/executor/` (`mod.rs` registry and `Run`, `spawn.rs` the one place a process starts, `output.rs` bounded capture, `unit.rs` transient units), wired into the poller (`agent/src/tasks/poller.rs`) and the ledger (`agent/src/tasks/ledger.rs`). Builds on #166 (P3-AGENT-LEDGER) and #167 (P3-TASK-CONTROLS: `cancel`, `poll_seconds`, `failed`/`not_run`).

### P3-A03

- **Registry.** `Registry` maps a catalog type id to a `TaskImpl`, fixed at build time. `TaskImpl::prepare` checks the parameters (`executor::parse` into a typed struct with `deny_unknown_fields`; any mismatch is `invalid_params`) and returns a `Job`, or the refusal reason; nothing runs. `tasks::IMPLEMENTED` stays empty and must equal `Registry::production`'s types (a test checks): the task types are #36 and #37. The poller refuses an unimplemented type `not_supported`.
- **Spawn API** (threat model section 8). A job runs `Program { path: &'static str, args: &'static [&'static str], operand: Option<ValidatedArg>, privilege }` through `Run::program`. `ValidatedArg` can only be made by a validator in `spawn.rs` (today a service unit name by the catalog's pattern) and always follows `--`. The agent's own helper calls use `Generated` values made only from a UUID, a step number, a number of seconds, or a 32-digit invocation id.
- **Execution.** `env_clear`, then exactly `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C`, `DEBIAN_FRONTEND=noninteractive`; working directory `/`; standard input `/dev/null`; standard output and error into one pipe; `process_group(0)`.
- **Timeout.** The smaller of the server's `timeout_seconds` and the catalog's, from the start of the run, on the monotonic clock. A watchdog thread sends `SIGTERM` to the group, waits 10 s (`TERM_GRACE`), then `SIGKILL`. Whatever is left in the group when the program exits is killed too. The program is reaped only after the watchdog is done (`waitid` with `WNOWAIT`), so its group id cannot be reused by an unrelated process while a signal may still be sent. Reported `timed_out` with a note line in the output.
- **Output.** The first and last 64,000 bytes are kept, the middle is counted and dropped as it arrives, and a marker line says how many bytes were cut; `output_truncated` is set. At most 131072 characters are sent (the contract's limit). The server truncates further to its own setting.
- **Cancel** (#31). While a task runs, the poller's `Control` sends progress every 15 s (`PROGRESS_EVERY`) and reads the `cancel` in the response. An interruptible type is stopped and reports `cancelled`; a type that is not is never stopped by a cancel (DEC-14). The poll's own `cancel` names a running task, and the poller polls only between tasks, so it is only logged. The poll's `poll_seconds` replaces the configured interval, clamped to `[task_poll]`'s `min_seconds` and `max_seconds`.
- **Shutdown.** An interruptible task is stopped and reported `failed`/`interrupted`. A direct child that is not interruptible gets 45 s (`SHUTDOWN_WAIT`, below systemd's 90 s stop timeout), then is stopped the same way. A transient unit that is not interruptible is left running (below).
- **Ledger.** A new step, `executing`, is written and flushed after the server's `run: true` and before anything runs (the threat model's proposed `acknowledged`, L2). Compaction keeps `unrun` for a task that never ran.
- **Closing a task that never ran** (the #34 handover, #31's contract). A `start` answered `run: false` with `state: queued` (the claim lapsed first) is recorded `failed`/`not_run` and reported at once, which the server accepts for a task this host claimed. A known id the server delivers again after it was reported is closed again: `failed`/`not_run` if the ledger has no `executing` record for it, `failed`/`agent_error` ("ran, or may have run") if it does. Nothing is run twice. A task recovered after a crash with only `received` is reported `not_run`; with `started`, `interrupted` (the server may have it running, where `not_run` is refused).
- **No shell, checked.** `agent/scripts/check-task-spawns.sh` (agent CI, "No shell in the task module") fails if `Command`, `.arg(`, `.args(`, `.env(`, or `.envs(` appear in `src/tasks` outside `executor/spawn.rs`, if `Command::new` appears there more than once, if any shell string, `"-c"`, `system(`, `popen`, or `libc::exec` appears, or if `spawn.rs` formats a string outside `Generated`'s constructors. Test code (files named `tests.rs`, and each `#[cfg(test)] mod tests { ... }` block up to its closing `}` in column 0) is left out; anything after such a block is checked again. `--self-test` (run first in CI) proves it catches a shell, an `.arg(` outside `spawn.rs`, code placed after a test module, and a `format!` in `spawn.rs`.
- **No hooks in release builds.** The poller's crash points, the test task types, and the privilege smoke tests are all `#[cfg(test)]`.
- **Tests.** `executor/tests.rs`: environment exactly the fixed set; `/`, closed standard input, own process group; exit status and output; 2 GiB of output bounded; a deadline kills the program and its children; a program ignoring `SIGTERM` is killed after the grace; the lower timeout wins; cancel stops an interruptible task and not another; shutdown; a program needing more privilege than its type never runs; strict parameter refusals; transient units (run, deadline, left running at shutdown, failed start, recovery). `poller/tests.rs`: a canary file proves refused tasks (unknown type, extra or command-like parameters, type not enabled) run nothing and an accepted one runs; `not_run` after a requeued start and on redelivery; the poll hint; progress and cancel; a unit left running is waited for after a restart and then reported.

### P3-A05

- **Model:** the agent's unit is unchanged. `read_only` and `service_manager` programs run as children of the agent inside its sandbox; `package_manager` programs run in a transient unit `fleet-agent-task-<id>-<step>.service` outside it, with fixed properties, the agent's credential and state hidden, and `RuntimeMaxSec=`. Each `Program` declares its privilege and runs only for a type whose catalog privilege is at least that. No `sudoers` file: DEC-03 keeps root.
- **Privilege table** and the option-by-option review: [`docs/operations/agent-task-privileges.md`](../../operations/agent-task-privileges.md).
- **`systemd-analyze security`:** 1.9 OK before and after (the unit did not change). The task unit's properties score 8.7, against 9.4 for a plain service running the same program.
- **Agent restart during a task unit** (threat model L8): the unit keeps running; the ledger keeps the task `started`; reconciliation polls for nothing while any of its units runs, then reports their exits and output (`nonzero_exit`, `timed_out`, or `interrupted` when every unit exited 0, because the job never saw its steps end) and removes the units.
- **Proven in CI:** `agent/scripts/task-privilege-smoke.sh` runs the unit-test binary's `privilege_smoke_*` tests as a service with every `[Service]` option of the real unit: a `read_only` child cannot write `/usr`; `systemctl restart` from inside the sandbox restarts a unit; a `package_manager` program in a task unit writes `/usr`, gets the fixed environment, cannot read `/etc/fleet-agent`, and is stopped at its deadline.
- **Left for the task issues:** "each task type works under the final unit file on the test VM" is checked by #36 and #37 as each type lands; #37 reviews the task unit's property list against real upgrades and may narrow it, and may give `apply_package_updates` its own recovery of the real outcome (the framework reports what the units did).
