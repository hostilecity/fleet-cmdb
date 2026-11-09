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
