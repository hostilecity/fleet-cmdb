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
