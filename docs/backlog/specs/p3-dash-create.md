# P3-DASH-CREATE: Dashboard: create-task flow with second factor

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P3-D01: Phase 3 dashboard mockups (create task, task list and detail, batch progress)

### Scope

Static HTML mockups in `docs/mockups/phase-3/`:

- Create-task flow, each step, including excluded hosts, batch confirmation, and the second-factor prompt
- Task list with filters; task detail with timeline, output, and reason codes
- Batch progress page with per-host counts
- Cancel dialog wording for queued, running-interruptible, and running-not-interruptible states
- Allowlist and limits settings
- Empty-allowlist and disabled-type states

### Acceptance criteria

- [ ] Owner has approved the mockups in the PR
- [ ] The wording makes it obvious exactly what each task will run
- [ ] Every item in FR-3.4 is represented

## P3-S08: Dashboard: create-task flow

### Scope

- Steps: choose task type; read what exactly it will do (the catalog's description, rendered as plain language); set validated parameters (form generated from the closed schema, errors in place); choose targets by tag or explicit selection, showing the resolved host list and any excluded hosts with reasons; confirm.
- Above the batch threshold, the operator confirms by typing the host count ([DEC-14](../../decisions/0014-task-trust-model.md)).
- Refuses to proceed when a type is disabled everywhere or the allowlist is empty, with an explanation.
- Server-side enforcement of every rule; the form is a convenience, not a control.

### Acceptance criteria

- [ ] There is no free-text field that is sent anywhere as a command
- [ ] Hosts that do not support or have not enabled the task type are shown as excluded
- [ ] A forged POST that bypasses the UI is rejected with the same validation (AC-3.1 via the dashboard endpoints)
- [ ] Confirmation requirements for large batches are enforced server-side

### As built (#32, owner decisions Q3 to Q13)

- **Pages.** `GET /tasks/new` (type), `/tasks/new/parameters`, `/tasks/new/targets`, `/tasks/new/confirm`, then `POST /tasks` (`TaskCreationsController`). Plain GET forms, no JavaScript (Q3); each step checks again everything chosen before it. "Tasks" is second in the top bar (Q1). Without a second factor the steps are replaced by an explanation (Q12).
- **Types.** The catalog's own names and descriptions, the time limit, whether it can be cancelled while running, its default on agents, and "hosts that will run it" (active hosts whose agent supports and enables it). A type is drawn unavailable, with why, when no host runs it, when it is `restart_service` and the allowlist is empty, or when the dashboard has no list for one of its parameters (it never offers a text box).
- **Parameters.** The restart service is a list from the allowlist with the tags each entry is for (Q5). `refresh_reports` has no parameters in the catalog (`docs/api/tasks/task-catalog.json`), so it collects all three reports and the mockup's report tick boxes are not drawn; adding them needs a catalog change and an agent release.
- **Targets.** By tag, or by picking hosts (search by name or hostname, at most 100 listed). The page shows the hosts that get the task and the hosts left out with the reason in words (`TaskBatches.preview`, the same checks as creation). Offline and stale hosts stay in with a warning (Q8). Hosts are shown by their operator-set name and hostname (threat model H11).
- **Confirm.** Plain steps per type and, folded, the programs the agent runs and the exact payload the server sends (Q9). The programs are the ADR 0015 and ADR 0016 drafts until P3-AGENT-TASKS and P3-AGENT-UPDATES fix the final lines; those issues update `cmdb/app/views/task_creations/guides/`. A warning that every host runs at about the same time (Q10). The typed host count above 3 hosts and the code box in one form (Q11).
- **Submit.** Needs `require_second_factor "create_task"` and the page's signed confirmation (`TaskConfirmation`). It is refused, and the confirmation drawn again with the reason, if the confirmation is missing or forged, another operator's, over 30 minutes old, or drawn for a different request, or if the hosts the request resolves to now differ from the ones shown (Q13, `TaskBatches.create!(expected_host_ids:)`). Its one-time id is stored on the batch (`task_batches.confirmation_token`, unique), so a double submit creates one batch (threat model H10). A forged POST gets the same validation as the form, with every problem listed.
- **Audit.** Every refused `POST /tasks` writes `task.creation_refused` ("Task creation refused") with the operator, the type if it is in the catalog, and the problems; never the values sent.
- **After.** The flow redirects to `GET /tasks/batches/:id`, a minimal batch page (tasks, states, hosts left out). `GET /tasks` is a minimal page with "New task" and recent batches. P3-DASH-TASKS (#33) replaces both at the same paths. Not built here: a fresh code for large batches (threat model H3 and open question Q3, awaiting the owner), and "Run a task on this host" on the host page (#33; it can link to `/tasks/new?target[host_ids][]=ID`, which the flow carries through).

## P3-S09: Second factor (TOTP) for task creation, cancellation, and allowlist changes

### Context

[DEC-06](../../decisions/0006-operator-authentication.md) and [DEC-14](../../decisions/0014-task-trust-model.md): sign-in is Google OAuth, and Google cannot be forced to re-authenticate (its OIDC supports `prompt` values `none`, `consent`, and `select_account` only, with no forced re-login or `max_age`). A hijacked operator session would otherwise be one click from fleet-wide execution, so the application adds its own second factor.

### Scope

- Enrolment of TOTP per operator (owner decision 2026-11-08: TOTP only, no passkeys), with recovery codes shown once, and enrolment itself protected by a fresh Google sign-in plus the existing session.
- A step-up check required before creating a task or batch, cancelling a task, and changing allowlists or limits: the operator must have passed the second factor within a short window (default 5 minutes), tracked server-side per session.
- Enforced on the server for **every** relevant endpoint, not only in the UI. Operators without an enrolled factor cannot create tasks; the UI says why.
- Documented recovery path for a lost authenticator (console or rake) that cannot be performed from the web.
- Rate limiting and audit entries for step-up attempts (success and failure).

### Owner decisions (2026-11-08, `docs/mockups/phase-3/index.html`)

- Codes: 6 digits, 30-second steps, SHA-1 (Q26); one step of drift either side; each code accepted once (Q30).
- Setting up: a fresh Google sign-in, meaning a new OAuth round trip for the same account within 10 minutes (Q27); the key shown once, as a server-drawn QR code and as text, uncached; 10 recovery codes, hashed, shown once, with the factor on before they are shown (Q28).
- A recovery code works anywhere a code is asked for, including moving to a new phone (Q25). Moving to a new phone asks for a current code or a recovery code, then the fresh sign-in.
- The step-up window is a fixed 5 minutes from the last accepted code, per session, not extended by use (Q29).
- 5 wrong codes in 15 minutes per operator lock the step-up for 15 minutes, in every browser (Q30). A lock holds inside an open window.
- "Your second factor" is under Settings (Q24). The console reset is `bin/rails second_factor:reset EMAIL=…`, audited (Q25, Q35).
- Audit actions as in `audit.html` (Q35): `second_factor.enrolled`, `.replaced`, `.recovery_codes_replaced`, `.step_up_passed`, `.step_up_failed`, `.locked`, `.recovery_code_used`, `.reset`.

### How later work uses it

Controllers declare `require_second_factor "create_task"` (or `"cancel_task"`, `"change_task_settings"`), optionally with `fresh: true` to ask for a code even inside the window (threat model H3, if the owner accepts it). The action's form renders `second_factors/prompt` and posts the code as `second_factor_code` with the rest of the form, so one submit checks the code and does the action (Q11). A refused request runs nothing and gets 403 (429 while locked); a controller may override `second_factor_refused` to show its own confirmation again.

### Acceptance criteria

- [ ] Creating a task without a recent second factor is rejected, including via a forged POST that skips the UI
- [ ] Cancel and allowlist endpoints enforce the same check
- [ ] Lost-authenticator recovery works and is audited
- [ ] Step-up attempts are rate limited and failures appear in the audit log
