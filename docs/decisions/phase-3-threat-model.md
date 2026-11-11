# Phase 3 threat model: allowlisted remote tasks

- Status: **First draft** ([P3-X01](../backlog/specs/p3-security.md), issue #38). Written before any Phase 3 code, so that it shapes the task API, the server controls, and the agent executor. Every later Phase 3 pull request updates the rows it touches; P3-X01 finalises the document and adds the no-arbitrary-shell review note.
- Requirements: `FR-3.1` to `FR-3.4`, `FR-S.1` to `FR-S.5`, `NFR-1`, `AC-3.1` to `AC-3.9`
- Decisions relied on: [ADR 0003](0003-agent-privilege.md), [0005](0005-hosting-tls-deployment.md), [0006](0006-operator-authentication.md) (TOTP only), [0014](0014-task-trust-model.md), [0015](0015-restartable-services.md), [0016](0016-package-update-policy.md), [0017](0017-agent-onboarding.md), [0018](0018-signed-agent-updates.md), [0023](0023-deploy-with-github-actions.md), [0024](0024-cloudflare-origin-ca-for-the-server.md)

This is not an ADR: it decides nothing by itself. Where it proposes a control that no ADR or spec contains, the row says **Proposed**, and the control becomes binding only when the owner accepts it and it is written into the spec or an ADR.

Names below are placeholders: `fleet.example.com` is the dashboard hostname, `fleet-vm.example.com` the server VM's internal hostname (which is also the agent API hostname, ADR 0024), and `vm-01.example.lan` a fleet VM.

## 1. What Phase 3 adds, and why it is the riskiest phase

Before Phase 3 the server can make an agent do three things: send reports, re-send reports on request (ADR 0013), and install a newer agent release signed by a key the server never holds (ADR 0018). Phase 3 adds a fourth: **run a catalog task as root on the VM**. The initial catalog (P3-S01) is:

| Task type | What it does on the VM | Default on the agent (ADR 0014) | Parameters |
|---|---|---|---|
| `refresh_reports` | Re-collect and send inventory, config, package reports | Enabled | None: always all three (P3-S01); any parameter is refused |
| `restart_service` | `systemctl restart -- <unit>` and check the unit is active | Disabled | `service`: strict pattern, in **both** allowlists, not protected (ADR 0015) |
| `apply_package_updates` | `apt-get update`, then `apt-get upgrade` under the ADR 0016 policy; never reboots | Disabled | None (ADR 0016) |

The core invariant (FR-3.1, AGENTS.md): **the server can never cause an agent to run a program, script, command line, or option of its choosing.** It can only name a catalog type compiled into the agent, with parameters that validate against a closed schema on both sides. Everything below is either protecting that invariant or limiting the damage of what remains possible within it: an attacker who controls the server or an operator session can still run any enabled catalog task, with valid parameters, on any host that enabled it.

### Status legend

| Status | Meaning |
|---|---|
| **Built** | Exists on `main` today (Phase 1 or 2 code), with tests |
| **Decided** | Required by an ADR, a requirement, or a Phase 3 spec, but not built yet (all of Phase 3) |
| **Proposed** | Proposed by this document; not in any spec or ADR yet. Needs the owner's acceptance (section 11) |

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Root on every fleet VM | The prize. The agent runs as root (ADR 0003) |
| A2 | Availability of fleet services | `restart_service` and `apply_package_updates` can cause outages even when used "legitimately" |
| A3 | Integrity of each VM's dpkg database | An interrupted `apt-get upgrade` can leave it half-configured (ADR 0016) |
| A4 | The embedded task catalog and agent code | Defines everything an agent will ever run; changes only through a signed release |
| A5 | Agent-local task config: enabled types, local service allowlist (`/etc/fleet-agent`, mode `0600`, root) | The agent's last line of refusal; the server cannot change it |
| A6 | Agent credentials (per host; plaintext only on the VM, SHA-256 digest on the server) | Authenticate a host; a stolen one lets an attacker act as that host |
| A7 | Operator sessions (encrypted cookie holding a random token; digest in `operator_sessions`) | A live session is one step from task creation |
| A8 | Operator TOTP secrets and recovery codes (server) and the authenticator (operator's device) | The step-up factor for task creation, cancel, allowlist changes (ADR 0006) |
| A9 | Release signing key (GitHub protected `release` environment) and the embedded public keys | The only path by which the server can cause new code to run (ADR 0018) |
| A10 | Server-side task state: catalog mirror, tasks, batches, allowlists, limits (PostgreSQL) | Decides what is offered to whom |
| A11 | Audit log and the agent's local task ledger | The record of who ran what, where, and with what result |
| A12 | Task output and results | Untrusted text from VMs, shown to the operator |
| A13 | The server VM and its deploy path (self-hosted runner, `deploy` user in the `docker` group, GitHub `production` environment) | Whoever deploys the server is the server |
| A14 | The Cloudflare account (tunnel, Access, Origin CA) | Terminates dashboard traffic; can issue certificates for the internal hostname (ADR 0024) |

## 3. Actors

| Actor | Legitimate role | Assumed capabilities if hostile |
|---|---|---|
| Operator | Creates, cancels, inspects tasks; edits allowlists | Trusted; may make mistakes (wrong target, wrong tag) |
| Session thief | None | Holds a live operator session (stolen cookie, malicious extension, unlocked laptop, XSS). Does **not** hold the authenticator |
| Phisher in the middle | None | Relays a live session and a live TOTP code (TOTP is phishable; accepted with ADR 0006's TOTP-only amendment) |
| Compromised server | Issues tasks, hosts releases | Full control of the Rails process, its environment (master key, Origin key), and the database. Cannot sign releases |
| Compromised PostgreSQL / DB role | Stores state | Can read and write every table, including tasks, allowlists, audit entries, TOTP secrets |
| Compromised fleet VM | Runs an agent for itself | Root on that VM: reads its own agent credential, can send any request the agent API accepts for that host, and can reach anything on the LAN, including port 443 of the server VM |
| LAN attacker | None | Any device on the internal network or VPN, without an agent credential |
| Tunnel VM attacker | Runs `cloudflared` | Sees dashboard requests in plaintext between Cloudflare and the origin TLS connection it opens |
| Cloudflare (or the owner's Cloudflare account) | Edge, Access, tunnel, Origin CA | Sees dashboard plaintext at the edge; can issue an Origin certificate for the internal hostname (ADR 0024) |
| Owner's GitHub account | Merges, deploys (CD on every push to `main`), approves releases | If compromised: can deploy any server code and approve a signed agent release |
| Dependency or toolchain author | Supplies crates, gems, actions, base images | Malicious update to a dependency |

## 4. Trust boundaries

```
 Operator browser ──(B1)── Cloudflare edge + Access ──(B2)── cloudflared on tunnel VM ──(B3: TLS, Origin cert)──┐
                                                                                                                │
 LAN / VPN clients ───────────────────────────(B4: same port 443, Host header decides)──────────────────────────┤
                                                                                                                ▼
                                                     fleet-cmdb container on server VM (Rails, Solid Queue jobs)
                                                          │ (B5)                       ▲
                                                          ▼                            │ (B6: TLS, per-host credential)
                                                     PostgreSQL container         fleet-agent on vm-01.example.lan (root,
                                                                                    hardened unit) ──(B7)── task child
                                                                                    processes / transient units
 GitHub: repo, CI, `release` env (signing key) ──(B8: signed release; agent verifies)──> agent binary + embedded catalog
 GitHub: `production` env, self-hosted runner ──(B9: SSH deploy)──> server VM
```

| ID | Boundary | What crosses it | What is checked there |
|---|---|---|---|
| B1 | Browser to Cloudflare | Dashboard HTTPS | Cloudflare Access policy (operator emails) |
| B2/B3 | Cloudflare to tunnel VM to origin | Dashboard requests, re-encrypted by `cloudflared` | Origin certificate (ADR 0024). The tunnel VM sees plaintext |
| B4 | LAN to server port 443 | Agent API and, with `Host: fleet.example.com`, the dashboard | `HostSeparation` (`cmdb/lib/middleware/host_separation.rb`): `/api` only on the agent hostname, dashboard only on the dashboard hostname. **Cloudflare Access is not on this path** (documented in `docs/operations/install-server.md`, security notes), so Google sign-in, the operator allowlist, and TOTP are the controls a LAN attacker faces |
| B5 | Rails to PostgreSQL | All state | One role (`cmdb`) that also owns the schema and runs migrations |
| B6 | Agent to server | Heartbeats, reports, task poll, start, progress, result | Agent: system store + Origin CA roots + optional `ca_file`, no opt-out (NFR-1). Server: per-host credential (`Api::V1::AuthenticatedController`), body size limit (64 KB default, `Api::V1::BaseController`), per-credential rate limit, schema validation |
| B7 | Agent to task execution | A catalog type id and validated parameters become fixed argument vectors | Embedded catalog, strict parameter types, local config, protected list (P3-A01, P3-A03, P3-A06) |
| B8 | Release pipeline to agent | Agent binaries (and therefore the catalog) | Minisign signature over the manifest against embedded keys, SHA-256, no downgrade (ADR 0018, `agent/src/release/mod.rs`) |
| B9 | GitHub to server VM | Server code and production secrets | Branch protection on `main`, environment restricted to `main`, fork-PR approval for the self-hosted runner |

## 5. Data flows

Each step names who enforces what. "Agent" checks hold even if the server is hostile; "server" checks hold only while the server is honest.

### F0. Enabling a task type on a VM (local, out of band)

1. The owner edits `[tasks]` in `/etc/fleet-agent/config.toml` on the VM: enabled types, local service allowlist, limits (P3-A01). Root on the VM is required.
2. Invalid config fails safe: nothing enabled (P3-A01).
3. The agent reports supported types, enabled types, and catalog version (P3-A01). The server uses this **only to decide what to offer**; it is a hint from an untrusted source, never a permission.

### F1. Task creation (operator to server)

1. Operator opens the create-task flow on `fleet.example.com` (P3-S08). Server-rendered form from the closed catalog schema; no free-text command field.
2. POST with Rails CSRF token. Server checks, in order: live operator session (Built), **TOTP step-up within the window** (default 5 minutes, per session, server-side; P3-S09), type exists in the server's catalog mirror, parameters validate against the closed schema (P3-S01), `restart_service` name is on the server allowlist and not protected (P3-S06), targets resolved from operator-set tags or explicit selection to `active` hosts advertising the type, excluded hosts listed (P3-S02), batch size ≤ 25 and typed host count above 3 (ADR 0014, P3-S08).
3. One transaction: batch, one task per host, each with expiry (default 24 h) and timeout from the catalog; audit entries `batch created` and `task created` with the operator as actor (P3-S07).

### F2. Claim (agent to server)

1. Heartbeat response carries a named "tasks available" directive (ADR 0020, P3-S03); the agent polls `POST /api/v1/tasks/poll` on `fleet-vm.example.com`.
2. Server authenticates the credential; the host is always the credential's host, never one named in the request (Built pattern in `AuthenticatedController`).
3. Atomic conditional update: one `queued`, unexpired task for this host becomes `claimed` with a lease; or the same already-claimed, unstarted task is returned again (P3-S03). Parameters and allowlists re-validated at claim; a task that no longer validates becomes `refused` (P3-S03, P3-S06). Audit: `claimed`, host as actor.
4. Payload: task id, type, parameters, deadline, catalog version. Nothing else (P3-S03).

### F3. Execution (agent)

1. Agent validates: type in the **embedded** catalog; type enabled locally; parameters parse into a typed struct with `deny_unknown_fields`, ranges, patterns; for `restart_service` the name is in the local allowlist and not protected (P3-A03, P3-A06). Any failure: `refused` result with a reason code, nothing executed.
2. Ledger: `received`, then `started` written and `fsync`ed **before** anything runs (P3-A02). A task id already in the ledger is never run again.
3. `POST /api/v1/tasks/:id/start`; only after the server accepts it does the task run (P3-A02, P3-S03). A cancelled task's start is refused and the agent drops it (P3-S05).
4. Execution: fixed absolute executable, fixed argument vector, no shell, `env_clear` plus a fixed set, fixed working directory, stdin closed, own process group, timeout = min(server deadline, catalog maximum), bounded output (P3-A03). One task at a time.

### F4. Result (agent to server to operator)

1. Ledger `finished`; `POST /api/v1/tasks/:id/result` retried until accepted; ledger `reported` (P3-A02).
2. Server: only the owning host may report; outcome enumerated; output truncated with marker, invalid UTF-8 and control characters sanitised, stored as inert text; identical resubmission accepted, conflicting one rejected and logged; terminal states immutable (P3-S04). Audit: `result received` with outcome (P3-S07).
3. Dashboard renders output escaped, under the existing strict CSP (P3-DASH-TASKS; CSP Built in `cmdb/config/initializers/content_security_policy.rb`).

### F5. Time-driven transitions (server jobs)

Every minute at least: expire queued tasks; return lapsed unstarted claims to `queued`; mark started tasks without reports `failed`/`lease_expired`; mark running tasks past deadline plus grace `timed_out`. System as audit actor (P3-S05, P3-S07).

### F6. Cancellation

Queued or claimed-unstarted: `cancelled` at once, start acknowledgement refused. Running and interruptible: cancel directive on next poll/progress response. Running and not interruptible: runs to completion, `cancel_requested` recorded, nothing further in the batch starts (ADR 0014, P3-S05). Requires TOTP step-up (P3-S09).

### F7. Catalog change (supply chain)

Shared catalog file (for example `docs/api/task-catalog.yml`) changed in a PR, catalog lint and contract tests in CI (P3-S01), agent built with the catalog embedded, release signed in the protected `release` environment after the owner's approval (ADR 0018), rolled out through canaries, server catalog mirror deployed. Neither the server nor the dashboard can add or widen a type at runtime.

## 6. Threats and mitigations

Columns: **Mitigation** is what stops or limits the threat; **Source** is the ADR, requirement, or spec that requires it; **Status** per the legend; **Proven by** is the test that must show it works.

### 6.1 Hijacked operator session (session thief, phisher)

| ID | Threat (STRIDE) | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| H1 | Thief with a live session creates a fleet-wide task (E) | TOTP step-up within 5 minutes, checked server-side on every create, cancel, allowlist, and limit endpoint, including forged POSTs | FR-3.4, ADR 0006, P3-S09 | Built (step-up check, P3-S09; called by the cancel and allowlist endpoints, #31, and by `POST /tasks`, #32) | P3-S09 AC "forged POST rejected"; P3-X02 direct-API case without step-up |
| H2 | Thief rides a step-up the real operator just completed (window reuse) (E) | Window tied to the server-side session record, not the cookie alone; short default (5 min) | P3-S09 | Built (P3-S09) | P3-S09 spec: step-up on session A does not authorise session B |
| H3 | Same, within the window, for a large batch | **Proposed:** require a fresh TOTP code (not the window) for any batch above the typed-count threshold (3 hosts) and for allowlist widening | — | Proposed | P3-S09 request spec |
| H4 | Operator has no TOTP enrolled; thief enrols their own authenticator and then has full task rights (E) | P3-S09 protects enrolment with "a fresh Google sign-in plus the existing session", but Google cannot be forced to re-authenticate (ADR 0006), so a hijacked browser can usually complete that. **Proposed:** first enrolment needs a one-time enrolment code issued from the server console (`bin/rails` task), like the first operator; re-enrolment needs the current factor or a recovery code | ADR 0006 | Proposed (open question Q1) | P3-S09: enrolment without the console code is refused |
| H5 | TOTP code replayed within its 30-second step, or brute forced (S) | Remember the last accepted time step per operator and refuse reuse; rate limit and audit attempts; lock step-up after N failures | P3-S09 (rate limit, audit); replay refusal **Proposed** | Built (P3-S09: one step of drift, 5 wrong codes in 15 minutes lock for 15 minutes, owner decision Q30) | P3-S09: same code twice fails; the 5th failure locks and is audited |
| H6 | Real-time phishing relays a TOTP code (S) | Accepted residual risk of TOTP-only (owner decision 2026-11-08). Limited by Access on the public path, the batch cap, agent opt-in, and the local allowlists | ADR 0006, ADR 0014 | Accepted | — |
| H7 | Recovery codes stolen or reused (S) | Shown once, stored as digests, single use; lost-authenticator recovery only from the console, audited | P3-S09, ADR 0006 | Built (P3-S09; HMACs keyed from `FLEET_ENCRYPTION_KEY`) | P3-S09 recovery AC |
| H8 | CSRF: a page the operator visits submits a create-task form (T) | Rails authenticity token; `SameSite=Lax` cookie (Built); step-up still required | NFR-1 | Built / Decided | P3-X02: POST without token rejected |
| H9 | XSS in the dashboard steals the session or drives the create form (E) | Strict CSP: `script-src 'self'` with nonces, no inline (Built); all output escaped (H/O rows) | NFR-1 | Built | O1 tests |
| H10 | Double submit or browser retry creates two batches (T) | A one-time id in each confirmation page's signed token, stored on the batch with a unique index; a second POST with the same token creates nothing and goes to the first batch | P3-S08 | Built (#32) | `spec/requests/task_creations_spec.rb` "creates one task per host" and "two submits of one confirmation at once" |
| H11 | Operator selects the wrong hosts because a VM reports a misleading hostname (S, from a compromised VM) | Target selection and the confirmation list use the operator-set host name, hostname, and tags (FR-1.1); nothing the agent reports names a host there | P3-S08 | Built (#32) | `spec/requests/task_creations_spec.rb` targets and confirm examples |

Residual: someone holding both a live session and the authenticator (or relaying both) can run any enabled task, within the batch cap, on hosts that enabled it. Agent-side opt-in (C1–C3) bounds what that achieves.

### 6.2 Compromised server or database issuing tasks

The server is assumed fully hostile here. The question is what the agent still refuses.

| ID | Threat | What the agent still enforces | Source | Status | Proven by |
|---|---|---|---|---|---|
| C1 | Sends an unknown type, or a type defined "dynamically" in the payload (E) | Only types in the catalog compiled into the binary; no runtime catalog loading; unknown type is `refused`, nothing runs | FR-3.1, P3-A01, P3-A03 | Decided | P3-X02 fake-server canary; P3-A03 AC |
| C2 | Sends extra fields, wrong types, oversize or injection strings (`; rm -rf /`, `$(...)`, `../`, control and bidi characters, option-like `--foo`) (T, E) | Typed structs with `deny_unknown_fields`, enums or strict patterns with max length; refused before any process starts | FR-3.1, P3-S01, P3-A03 | Decided | P3-X02 fuzz of both validators; P3-A06 "option-like name refused" |
| C3 | Runs a disabled risky type (`apply_package_updates`, `restart_service`) on a VM that did not opt in (E) | Local `[tasks]` config; default enables only `refresh_reports`; invalid config enables nothing | ADR 0014, P3-A01 | Decided | P3-A01 AC "not enabled by default" |
| C4 | Restarts a service not on the VM's own allowlist, or a protected one (agent unit, `ssh`/`sshd`, `systemd-*`, networking, `dbus`) (E, D) | Both allowlists must permit; protected list always wins; the agent checks its own list and the protected list when the task arrives, whatever the server sent, and refuses with nothing run | FR-3.1, ADR 0015, P3-A06 | Built (#36) | AC-3.9; `agent/src/tasks/restart_service.rs` `refused_names_run_nothing`, `the_agents_own_unit_is_refused_by_default_and_when_enabled`, and `privilege_smoke_restart_service_*` under the real unit |
| C5 | Abuses `systemctl` semantics with a valid-looking name: glob (`ssh*`), another unit type (`reboot.target`, `ssh.socket`), an alias that resolves to a protected unit, a template instance (D, E) | The pattern accepts only `[A-Za-z0-9][A-Za-z0-9_.@-]{0,247}` ending in `.service` (catalog), so no glob and no other unit type; exact string match against the local allowlist (a template instance must be listed by its full name); before anything runs, the agent follows the symbolic links named after the unit, and after its template, in every directory of systemd's unit search path, and refuses `protected_service` if any link in a chain names a protected unit (`messagebus.service` to `dbus.service`), or if a link with a protected name leads to the unit (`ssh.service` to `remote-login.service`; review of #169). The file system is read instead of `systemctl show -p Id -p Names`, so the refusal is decided with nothing run; aliases are symbolic links in those directories (`systemd.unit(5)`) | ADR 0015, P3-A06 | Decided (#36) | `agent/src/tasks/restart_service.rs` `refused_names_run_nothing` (`reboot.target`, `ssh*.service`, `ssh.socket`, aliases of `dbus.service`, `ssh.service`, a two-link chain to `systemd-journald.service`, a template aliased to `sshd@.service`, and reverse aliases: `ssh.service`, `dbus.service` through a chain, and `sshd@.service` pointing at the listed unit or its template) |
| C6 | Sends a server "deadline" far in the future or past to defeat timeouts (D) | Timeout = min(server deadline, catalog maximum); the agent measures it with a monotonic clock | P3-A03 | Decided | P3-A03 timeout AC |
| C7 | Re-sends a task the agent already ran, under the same id (T) | Ledger: an id already recorded is never run again | FR-3.2, P3-A02 | Decided | P3-X03; P3-A02 AC |
| C8 | Re-sends the same intent under a **new** id, many times (D) | Not preventable by the agent: a new id is a new task. Bounded by one task at a time, the catalog timeout, and the local opt-in | ADR 0014 | Accepted | — |
| C9 | Pushes an old, vulnerable agent release to regain a removed capability (E) | Agent never downgrades; verifies the signature itself | ADR 0018 | Built | P1-AGENT-UPDATE tests |
| C10 | Pushes a release with a wider catalog (E) | Impossible without the release key, which is never on the server | ADR 0018, NFR-1 | Built | — |
| C11 | Asks for secrets through task output (I) | Tasks receive no secrets in environment or arguments; `env_clear` (FR-3.3, P3-A03). A direct task child running as root could still read `/etc/fleet-agent/config.toml`; no catalog task prints files. Transient task units set `InaccessiblePaths=-/etc/fleet-agent -/var/lib/fleet-agent` (F-1, P3-A05) | FR-3.3, P3-A03 | Built (#35) | `agent/src/tasks/executor/tests.rs` "the environment is exactly the fixed set"; `scripts/task-privilege-smoke.sh` "cannot read the agent's credential" |
| C12 | Lies to the operator: shows fake results, hides tasks, forges or deletes audit entries (R, T) | Not preventable from the agent. The agent's ledger and journal on each VM are an independent record the server cannot rewrite. Audit table triggers (Built, `cmdb/db/triggers/`) stop application bugs, not a hostile process that owns the schema | FR-S.3 | Built (triggers) / Accepted | — (see A3, Q5) |
| C13 | Reads TOTP secrets from the database to pass step-up (S) | Irrelevant to a compromised server (it need not pass step-up), but relevant to a **database dump or backup**. **Proposed:** encrypt TOTP secrets with Active Record encryption, keys from the Rails credentials (not in the database); recovery codes as digests. Built with the key in `FLEET_ENCRYPTION_KEY` rather than the credentials file, which no deployment uses (`docs/operations/configuration.md`) | P3-S09 | Built | P3-S09 model spec: secret column is ciphertext |
| C14 | Direct database write inserts a task that bypassed validation and step-up (T, E) | Claim-time re-validation on the server (P3-S03): every poll, and the start request, check the task against the current catalog and server policy (`Task#refusal_reason` in `AgentTasks`) and refuse it, with the system as actor, if it fails; the agent's own checks (C1–C5) hold regardless | P3-S03 | Built | `spec/requests/api/tasks_spec.rb` "refuses at claim time" |
| C15 | Uses `apply_package_updates` to install, remove, or downgrade a package of its choosing, pass apt an option, or reboot the VM (E) | The type has no parameters (catalog, DEC-16): the agent refuses any (`invalid_params`). Every apt-get vector is fixed in `agent/src/tasks/apply_updates/apt.rs`: `update`, then `upgrade` with `--no-remove`, no new packages, local configuration kept, holds respected; never `dist-upgrade`. Nothing reboots. What it upgrades to is whatever the VM's own APT sources offer; Debian's archive signing is the control there (residual risks) | DEC-16, P3-AGENT-UPDATES | Built (#37) | `apply_updates/tests.rs` "bad parameters ... are refused with nothing run"; `apt.rs` "every program is fixed and follows the policy" |

Residual: a compromised server can run any enabled catalog task, with any parameters the agent accepts, on every host that enabled it, at a time of its choosing: package upgrades fleet-wide at once (A2, A3) and restarts of every locally allowlisted service. ADR 0014's consequence applies: each enabled type on a VM is a deliberate local choice and should be made knowing this.

### 6.3 Compromised VM attacking the server or other hosts

| ID | Threat | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| V1 | Polls, starts, or reports on another host's task by guessing ids (S, I) | Host is always the credential's host; a task is looked up only among that host's tasks, so another host's task is the same 404 as an unknown id on every endpoint (`Api::V1::TasksController`) | FR-S.2, P3-S03, P3-S04 | Built | `spec/requests/api/tasks_spec.rb` (each endpoint); P3-X02 |
| V2 | Submits a forged result for its own task (success while nothing ran; fake `reboot_required`) (S, R) | Accepted: a VM is authoritative only about itself. Results are labelled as agent-reported; agent times stored separately | P3-S04 | Accepted | — |
| V3 | Submits markup, scripts, ANSI or bidi control sequences in output, reasons, or details to attack the operator's browser (T, E) | See O1–O4 | NFR-1, FR-3.3 | Decided | O rows |
| V4 | Floods the API (poll, result, progress) to exhaust the server or database (D) | Per-credential rate limit and body size limits (Built for existing endpoints); the result endpoint needs its own `max_body_bytes` sized to the output limit, not the 64 KB default; output truncated server-side regardless | FR-S.2, P3-S04 | Built (pattern) / Decided | P3-S04 oversize AC; P3-X02 |
| V5 | Exploits a parser or validation bug in the agent API to execute code on the server, then uses the server against the fleet (E) | Bodies parsed with size limits before Rails params; JSON Schema validation; Brakeman and `bundler-audit` in CI (Built). This is the main pivot from one VM to all VMs; P3-X01's dependency audit and the review cover the new endpoints | NFR-1, P3-X01 | Built / Decided | P3-X02 malformed bodies |
| V6 | Lies in its capability report to be targeted, or to hide (S) | Capability report only decides what is offered; the agent re-checks locally | P3-A01 | Decided | — |
| V7 | Reaches the dashboard origin directly (`Host: fleet.example.com` to the server's port 443), skipping Cloudflare Access (S) | Documented and accepted for LAN and VPN clients (`install-server.md`): Google sign-in, the allowlist, and TOTP still apply. **Proposed for Phase 3:** decide whether dashboard requests must carry a valid Cloudflare Access JWT (`Cf-Access-Jwt-Assertion`) in production, which would make Access a real control on B4 | ADR 0024 | Accepted (Phase 1) / Open | Q2 |
| V8 | Spams the unauthenticated onboarding endpoint, or presents itself as a re-enrollment of another host (S, D) | Rate limit, open-request cap, operator approval with code match and facts (ADR 0017) | ADR 0017 | Built | P1-ONBOARD tests |
| V9 | Clones its disk to impersonate another host, or a re-enrolled or retired host receives tasks queued for the previous machine (S) | `machine-id` mismatch warning (FR-S.1, Built). Revoking a credential, starting a re-enrollment, or retiring a host cancels its queued and claimed tasks, audited with the same actor (`Host::TASK_CANCELLING_EVENTS`, P3-S05) | FR-S.1, P3-S05 | Built | `spec/services/task_cancellation_spec.rb` (V9) |
| V10 | Attacks other VMs over the LAN (E) | Out of this system's control. Agents open no inbound ports (design principle); the system adds no new listening service on VMs | Requirements §2 | Built | — |

### 6.4 Replay and duplicate claims

| ID | Threat | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| R1 | Two concurrent polls for one host both claim the same task (T) | Every task request locks the host row (`AgentHostLock`), so one host's polls run one at a time; the claim also takes the task `FOR UPDATE SKIP LOCKED`; at most one claimed or running task per host | P3-S03 | Built | `spec/services/agent_tasks_concurrency_spec.rb`; P3-X02 |
| R2 | Agent restarts and receives the same task again (T) | Unstarted claims are redelivered on purpose, with a fresh lease; the ledger stops a second run; a running task blocks the poll and is never redelivered (`AgentTasks.poll!`) | FR-3.2, P3-S03, P3-A02 | Built (server) / Decided (agent) | `spec/requests/api/tasks_spec.rb` (AC-3.3); P3-X03 matrix (≥100 runs) |
| R3 | Network replay of agent requests (S, T) | TLS (B6); `start` and `result` idempotent on the server | NFR-1, P3-S03, P3-S04 | Built (TLS) / Decided | P3-S04 "re-sending changes nothing" |
| R4 | Conflicting second result (for example `succeeded` then `failed`) (T, R) | Rejected and logged; terminal states immutable | P3-S04 | Decided | P3-S04 AC |
| R5 | Replayed operator POST (H10), replayed TOTP code (H5) | See H5, H10 | P3-S08, P3-S09 | Built (H5 in P3-S09, H10 in #32) | See H5, H10 |

### 6.5 Leases, expiry, timeouts: races

| ID | Race | Required outcome | Source | Status | Proven by |
|---|---|---|---|---|---|
| L1 | Task expires while a poll is claiming it | The claim's `SELECT ... FOR UPDATE SKIP LOCKED` includes `expires_at > clock_timestamp()`: **database time** in the same statement. Once locked, expiry (P3-S05) cannot touch the row; a claimed task is not redelivered after its expiry either | AC-3.8, P3-S03 | Built | `spec/requests/api/tasks_spec.rb` AC-3.8 examples |
| L2 | Agent writes `started`, sends `start`, the request is lost, the lease lapses and the job returns the task to `queued` | The agent must not run without the server's acceptance of `start`. The server answers `run: false` with `state: queued` and changes nothing (P3-S05, Built); on the next poll the agent receives the same id, finds it in the ledger, does not run it, and closes it with `failed`/`not_run`, which the server accepts for a claimed task, or a queued one this host claimed (never a running one). The ledger step `executing` (the proposed `acknowledged`) is written after the server's `run: true` and before execution: the agent sends `not_run` for a delivered id it never executed and `agent_error` for one it may have. A `start` answered `queued` is closed with `failed`/`not_run` at once (#35) | P3-A02, P3-S05, P3-A03 | Built | `spec/requests/api/tasks_spec.rb` "back in the queue"; P3-X03 kill point "after started, before ack" |
| L3 | Operator cancels while the agent is between `started` and `start` | Server refuses `start`; the agent records that and drops the task; nothing runs | P3-S05 | Built | `spec/services/task_cancellation_spec.rb` "refuses its start"; P3-X03 |
| L4 | Lease lapses on a task that is really running (agent offline, apt still running) | Server marks `failed`/`lease_expired` (P3-S05, `TaskLeases`) when the agent has not been heard from since the deadline; the task is not redelivered; a late result is kept in `task_late_results` (one per task, immutable) and does not change the terminal state | P3-S04, P3-S05 | Built | `spec/requests/api/tasks_spec.rb` "keeps a late result"; `spec/services/task_leases_spec.rb` |
| L5 | Server marks `timed_out` before the agent's own timeout fires (clock skew, slow network) | Server grace period after the deadline; agent timeout ≤ server deadline (C6); late result annotated | P3-S05 | Built (server) | `spec/services/task_leases_spec.rb` (AC-3.5 server half) |
| L6 | The jobs run twice at once, or the job races a poll | Jobs idempotent and safe concurrently: each task taken `FOR UPDATE SKIP LOCKED` in its own transaction, and every transition checks the expected state under the lock (`TaskLeases`) | P3-S05 | Built | `spec/services/task_leases_concurrency_spec.rb` |
| L7 | Agent update starts while a task is running, or a task is claimed mid-update | Update deferred while a task is in flight; claims blocked until the update is confirmed or rolled back | ADR 0018, P3-A02 | Decided | P3-A02 spec; P3-X03 |
| L8 | Agent restarts while `apply_package_updates` still runs in a transient unit (F-2) | A transient unit that cannot be interrupted is left running when the agent stops; the ledger keeps the task `started`. Reconciliation finds its units (`fleet-agent-task-<id>-<n>`), polls for nothing while one runs, then reports their exits and output and removes them (#35). The task type reads the exits by step (#37): an upgrade that ended with 0 is `succeeded` (with `reboot_required` from the flag file, and a package report), a failed one `nonzero_exit` or `lock_timeout`, one that reached its limit `timed_out` with the repair guidance, and an index refresh alone `interrupted` | P3-A03, P3-AGENT-UPDATES | Built | `executor/tests.rs` "recovery waits for a running unit"; `apply_updates/tests.rs` "a recovered upgrade that ended with 0 succeeded"; `scripts/vm-test.sh` "Agent restarted during the upgrade (L8)" |

### 6.6 Malicious results and output rendering

| ID | Threat | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| O1 | Output with HTML or script injected into the dashboard, including through Turbo Stream broadcasts of live batch progress (E) | ERB escaping everywhere (no `html_safe`/`raw` on output; none exists in `cmdb/app` today); broadcasts render the same escaped partials; strict CSP as a second layer | NFR-1, FR-3.3, P3-DASH-TASKS | Built (CSP) / Decided | P3-DASH-TASKS "markup renders as text"; system spec through the broadcast |
| O2 | Terminal escape sequences, Unicode bidi overrides, or zero-width characters that make output read differently from what it says (S) | Server sanitises at storage (`TaskOutput`, P3-S04): invalid UTF-8 replaced, terminal escape sequences and control characters other than tab and newline removed, and bidi overrides and isolates (U+202A–U+202E, U+2066–U+2069) removed. **Proposed:** zero-width characters shown as visible escapes in the dashboard (P3-S10) | P3-S04 | Built / Proposed | `spec/models/task_output_spec.rb` |
| O3 | Output served as a download is sniffed as HTML (E) | **Proposed:** any raw output download is `text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` | — | Proposed | Request spec |
| O4 | Agent-supplied reason text or structured details carry free text | Reason codes are an enumeration per outcome in `task-result.request`; the four known details validate against the schema (booleans and service or report names by pattern); an unknown detail key is ignored and not stored (DEC-08) | P3-S02, P3-S04, ADR 0008 | Built | `spec/requests/api/tasks_spec.rb` "keeps only the details it knows"; P3-X02 |
| O5 | Output lands in logs or the audit log (I, T) | Output is never logged or copied into audit entries; entries reference the task. The result-conflict log line names the task, outcome, and state only | P3-S04, P3-S07, NFR-1 | Built | `spec/requests/api/tasks_spec.rb`; `spec/services/task_audit_trail_spec.rb` |
| O6 | Gigabytes of output exhaust agent memory or server storage (D) | Bounded capture on the agent (first and last 64,000 bytes, a marker line with the count cut, at most 131072 characters sent); truncation on the server | FR-3.2, P3-A03, P3-S04 | Built | `executor/tests.rs` "gigabytes of output are bounded" (2 GiB); P3-S04 oversize |

### 6.7 Denial of service

| ID | Threat | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| D1 | Fleet-wide `apply_package_updates` or `restart_service` at once takes services down (A2) | Batch cap 25, typed count above 3, agent opt-in. **Proposed:** a per-batch concurrency limit (for example N hosts running at a time, the rest wait queued) and halt-on-failure, mirroring agent update rollouts | ADR 0014 | Decided / Proposed (Q4) | P3-S02 spec |
| D2 | Many batches in quick succession bypass the per-batch cap | **Proposed:** a limit on open (non-terminal) tasks per host and a rate limit on task creation per operator | — | Proposed | P3-S02 spec |
| D3 | A task holds the dpkg lock forever, or waits for it forever (A3) | The agent waits at most 5 minutes for the locks of apt and dpkg (`fcntl` probe), and apt-get waits at most 5 minutes more (`DPkg::Lock::Timeout`), then `lock_timeout` with nothing upgraded; 60-minute deadline; the unit is stopped (`SIGTERM`, `SIGKILL` 60 s later) and the result says to run `dpkg --configure -a` | ADR 0016, P3-AGENT-UPDATES | Built (#37) | `apply_updates/tests.rs` lock and deadline tests; `scripts/vm-test.sh` "Package manager lock held", "Forced timeout ends the process tree" |
| D4 | A task's child processes outlive the timeout | Own process group; a watchdog thread sends `SIGTERM`, waits 10 s, then `SIGKILL` to the group, and kills what is left of the group when the program exits; the program is reaped only after that, so its group id cannot be reused meanwhile. A transient unit has `RuntimeMaxSec=` and `KillMode=control-group`, and is stopped at the deadline. A process that leaves the group with `setsid` escapes the group kill, but stays in the agent's cgroup, which systemd kills on stop (#35) | P3-A03 | Built | `executor/tests.rs` "killed with its children", "ignores SIGTERM"; `task-privilege-smoke.sh` deadline |
| D5 | Ledger or state directory fills the VM's disk | Ledger compaction; bounded records | P3-A02 | Decided | P3-A02 spec |
| D6 | Restarting the network, `dbus`, `ssh`, or the agent itself cuts the VM off (A2) | Protected list (ADR 0015); C5 alias check | ADR 0015 | Built (#36) | P3-A06 (see C4, C5) |
| D7 | `needrestart` or package maintainer scripts restart services during `apt-get upgrade`, contradicting "never restarts services" | `NEEDRESTART_MODE=l` (list only) in every task's fixed environment, so needrestart's apt hook only lists; the agent runs `needrestart -b -r l` itself to report `services_needing_restart`. `NEEDRESTART_SUSPEND` is not set: list mode already restarts nothing, and the agent's own needrestart run must not be skipped. Maintainer scripts restarting their own daemon remain normal Debian behaviour (Q6) | ADR 0016 | Built (#37); Q6 open | `scripts/vm-test.sh` "Package updates applied": the service needrestart names is not restarted |

### 6.8 Supply chain and the catalog

| ID | Threat | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| S1 | A PR widens a catalog entry (new free-form parameter, `command` field, open schema) | Catalog lint (rejects `command`, `cmd`, `shell`, `script`, `args`, `exec`, `path`, free-form strings, `additionalProperties: true`); contract test that server and agent catalogs equal the shared file | FR-3.1, P3-S01 | Decided | P3-S01 lint ACs, in CI |
| S2 | Catalog change reaches agents without review | Requires a signed agent release, approved by the owner in the protected `release` environment (ADR 0018). **Proposed:** a CODEOWNERS rule (owner review required) on the catalog file, the agent task module, `agent/trust/`, `agent/release-keys/`, and the systemd unit, plus the PR-template checklist P3-S01 asks for | ADR 0018, P3-S01 | Built (release env) / Proposed | Repository settings check in P3-X01 |
| S3 | Owner's GitHub account compromised: deploys hostile server code (CD on every push to `main`) and approves a signed release with a wider catalog (E) | The single strongest trust anchor (ADR 0018 consequences): two-factor authentication, required approval, tag protection, branch protection (P1-RELEASES). Signed releases do not help against this actor | ADR 0018, ADR 0023 | Built (process) / Accepted | P1-RELEASES checklist |
| S4 | Malicious dependency in the agent or server | `cargo audit --deny warnings` (Built, `agent-ci.yml`), `bundler-audit` and Brakeman (Built, `bin/ci`), Dependabot, `--locked` builds; dependency review for new crates in the task path; P3-X01's dependency audit | NFR-1, P3-X01 | Built / Decided | CI |
| S5 | A fork PR runs on the self-hosted runner on the LAN | Fork-PR approval required; runner limited to `cd.yml` on `main` where possible (`install-server.md`) | ADR 0023 | Built (documented) | — |
| S6 | The Cloudflare account is taken over: Access disabled, an Origin certificate issued for `fleet-vm.example.com` to impersonate the server to agents (needs LAN or DNS position too) (S) | Accepted in ADR 0024 (same party already terminates dashboard traffic). Agents still refuse unsigned binaries and unknown task types, so the impersonator gets no more than a compromised server (6.2) | ADR 0024 | Accepted | — |
| S7 | Fault-injection hooks shipped in a release binary give the server a lever (E) | Test-only cargo feature; CI check that the release binary lacks it. So far every hook (the poller's crash points, the test task types, the privilege smoke tests) is `#[cfg(test)]` and absent from release builds (#35) | P3-A03, P3-X03 | Decided | P3-X03 AC |

### 6.9 Audit completeness and repudiation

| ID | Threat | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| A1 | A transition happens without an audit entry, or with the wrong actor (R) | Checklist spec walking every transition; operator, host, or system actor | FR-3.4, FR-S.3, P3-S07 | Built | `spec/services/task_audit_trail_spec.rb` |
| A2 | Step-up attempts, allowlist and limit changes are not attributable | Audited with before and after values; step-up success and failure audited | P3-S06, P3-S09 | Built | `spec/models/task_settings_spec.rb`; P3-S09 specs |
| A3 | A hostile server or DB role deletes or rewrites audit entries (R, T) | Append-only triggers (Built) stop the application, not the schema owner, which is the same `cmdb` role that runs migrations. Independent record on each VM: the agent's ledger and its journal lines for every received, refused, started, and finished task. **Proposed:** the agent logs each task decision to the journal with task id, type, parameters, and outcome; and **open:** ship audit entries off the server (Q5) | FR-S.3, NFR-4 | Built / Proposed / Open | P3-A02 log spec |
| A4 | Retention job prunes task audit entries | Guard spec | P3-S07, ADR 0007 | Built | `spec/services/task_audit_trail_spec.rb` "retention never prunes them" |
| A5 | Agent-reported times used for ordering or liveness | Server time authoritative; agent times stored separately | Requirements §3 | Built | P3-S04 |

### 6.10 Edge, tunnel, and server host

| ID | Threat | Mitigation | Source | Status | Proven by |
|---|---|---|---|---|---|
| E1 | Tunnel VM compromised: reads operator cookies and TOTP codes in plaintext as they pass, then relays (S, I) | TOTP codes are single-use within their step (H5) and expire in 30 s, but a live relay still works. Session cookies are usable from the LAN (V7). Treat the tunnel VM as part of the dashboard's trust base: no other workloads, patched, ideally `restart_service` and `apply_package_updates` enabled there only deliberately | ADR 0024 | Accepted / Proposed hardening | — |
| E2 | Server VM or `deploy` user compromised (`docker` group = root) (E) | Equivalent to a compromised server (6.2) | ADR 0023 | Accepted | — |
| E3 | Origin certificate key leaked (it is a GitHub secret) | With LAN or DNS position, impersonates the server to agents: same bound as 6.2 | ADR 0024 | Accepted | — |

## 7. STRIDE by component

An index of the rows above, so each component's owner can check coverage.

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| Operator browser and session | H5, H6, H11 | H8, H10 | A2 | E1 | — | H1–H4, H9 |
| Cloudflare, Access, tunnel VM | S6, E1 | — | — | E1 | — | V7 |
| Server: dashboard and task creation | H4, H5 | H10, C14 | A1, A2 | O5 | D1, D2 | H1–H3 |
| Server: agent API (poll, start, result) | V1, V9 | R1–R4, V2 | V2 | V1 | V4 | V5 |
| Server: jobs and state machine | — | L1–L6 | A1 | — | — | — |
| PostgreSQL | C13 | C14, A3 | A3 | C13 | — | — |
| Agent: poller and ledger | — | C7, R2, L2, L3, L7, L8 | A3 | — | D5 | — |
| Agent: executor and tasks | — | C2 | — | C11 | C6, D3, D4, D6, D7 | C1–C5, S7 |
| VM local config | — | C3, C4 | — | — | — | — |
| Release pipeline, GitHub, dependencies | — | S1, S2, S4 | — | — | — | S3, S5, C9, C10 |
| Operator's TOTP | H5, H7 | — | — | C13 | — | H4 |

## 8. The no-arbitrary-shell invariant and how it is checked

### Statement

1. No server route or parameter that reaches task creation accepts a command, script, path, executable name, option, or environment variable (FR-3.1, AC-3.2).
2. The poll payload carries only task id, type id, schema-valid parameters, deadline, and catalog version (P3-S03).
3. Every process the agent spawns uses an absolute executable path fixed in the agent's code, a fixed argument vector, no shell, and no task parameter in an executable or option position. A parameter can only select among implemented behaviours or fill one validated argument **after** an end-of-options marker (`--`) (P3-A03).
4. The agent never loads task definitions at runtime (P3-A01).

The one place server input already influences what the agent runs is the update path (ADR 0018): the version in the `agent_update` directive becomes a path component of the staged binary, which the agent executes for its self-test (`run_self_test` in `agent/src/update/stage.rs`) and which later becomes `current`. It is safe because the version must parse as strict SemVer, the binary must match a manifest signed by an embedded release key, and the version must not be older than the running one. The supervisor that `systemd-run` starts (`agent/src/update/mod.rs`) is the running version's own binary. P3-X01's review lists this explicitly as the documented exception, not as a task path.

### Layers that enforce it

| Layer | Mechanism | Source | Status |
|---|---|---|---|
| Catalog | Closed schemas; lint rejecting command-like names and free-form strings; server and agent catalogs equal the shared file | P3-S01 | Decided |
| Server models | No column or attribute on tasks or batches can carry a command; a request with a command-like field is rejected without creating records | P3-S02 | Decided |
| Server API | Poll serializer emits only the five fields; schema in `docs/api/schemas/v1` with `additionalProperties: false`; contract tests | P3-S03, NFR-5 | Decided |
| Agent types | Per-type parameter structs with `deny_unknown_fields`, through `executor::parse` (any mismatch is `invalid_params`) | P3-A03 | Built (framework; the types come with #36, #37) |
| Agent spawn API | **Proposed:** a single spawn function for tasks whose program is `&'static str` (as `agent/src/facts/host.rs`'s `Command` already uses `&'static [&'static str]`), whose arguments are `&'static str` except for one `ValidatedArg` newtype that can only be built by a validator and is always placed after `--`. This turns point 3 into a compile-time property. Built as `executor::spawn`: `Program { path: &'static str, args: &'static [&'static str], operand: Option<ValidatedArg> }`, and for the agent's own `systemd-run`, `systemctl`, and `journalctl` calls, `Generated` values made only from a UUID, a number, or 32 hex digits. Both newtypes have private fields | P3-A03 | Built (#35) |
| Static check | CI fails on `Command::new("sh")`, `"/bin/sh"`, `"-c"`, `format!` or string concatenation used to build a command line, in the task module. Built as `agent/scripts/check-task-spawns.sh` (non-test code of `src/tasks`): `Command`, `.arg(`, `.args(`, `.env(` only in `executor/spawn.rs`, one `Command::new`, no shell strings, no `format!` there outside `Generated`'s constructors | P3-A03 AC | Built (#35) |
| Adversarial tests | Hostile tasks from a fake server; canary file shows nothing ran | P3-X02 | Decided |

### Review procedure (P3-X01's review note)

1. **Server routes:** list every route under `/api/v1/tasks` and every dashboard route reaching task, batch, allowlist, or settings creation (`bin/rails routes`); for each, list the permitted parameters and show none is a command, script, path, executable, option, or environment. Include Turbo and Action Cable channels.
2. **Agent spawns:** enumerate every `std::process::Command::new`, `systemd-run`, and `systemctl` call in non-test code. Today (before Phase 3) they are: the facts collectors through `facts::host::Command` (`systemd.rs`, `sshd.rs`, `updates.rs`), `packages.rs` (`dpkg-query`), `install/systemd.rs` (`systemctl`, `systemd-run`), and `update/stage.rs` (the staged binary's `self-test`). Phase 3 adds the task spawns. For each: absolute path, fixed vector, no shell, where any non-constant argument comes from and how it is validated.
3. **Search:** `sh -c`, `/bin/sh`, `bash`, `Command::new(` with a non-literal, `format!` feeding an argument list, `eval`, `system(`, backticks, `%x`, `Open3`, `Kernel#exec`, `IO.popen`, `spawn` in `cmdb/`, ERB or string templates producing commands. Note: `agent/src/facts/host.rs` has a test-only helper `sh()` running `/bin/sh -c` inside `#[cfg(test)]`; the CI static check must cover non-test code (or exclude `#[cfg(test)]` modules explicitly) and the review must confirm it is absent from the release binary.
4. **CI:** confirm the catalog lint, contract test, static check, and P3-X02/X03 run on every PR touching `agent/`, `cmdb/`, or `docs/api/`.

## 9. Findings from the current code that Phase 3 must address

Concrete facts about `main` (with PR #150) that change how Phase 3 should be built.

| ID | Finding | Consequence | Proposal |
|---|---|---|---|
| F-1 | `fleet-agent.service` sets `ProtectSystem=strict`, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, `NoNewPrivileges=yes`, `SystemCallFilter=@system-service ~@privileged @resources` (`agent/src/install/fleet-agent.service`; exposure 1.9) | `apt-get upgrade` and maintainer scripts cannot run inside this sandbox (they write `/usr`, `/etc`, `/boot`, `/var`, change ownership, use setuid helpers). Relaxing the main unit for one task would loosen it for all agent code all the time | Keep the main unit as it is. Run `apply_package_updates` as a **transient unit** started with `systemd-run` (the pattern the update supervisor already uses), with a fixed unit name per task id, fixed properties (`RuntimeMaxSec=`, `KillMode=control-group`, `PrivateTmp=`, `ProtectHome=read-only`, `InaccessiblePaths=/etc/fleet-agent /var/lib/fleet-agent`), the fixed environment, and a fixed `apt-get` vector. Decide per task in P3-A05's privilege table. **Done in #35:** see `docs/operations/agent-task-privileges.md` |
| F-2 | The agent can already ask systemd over `AF_UNIX` to start transient units as root (`systemd-run` for the update supervisor) | The unit's sandbox is not a boundary against **code execution inside the agent process**: root over the system bus can start any unit. The sandbox guards against mistakes and limits a non-exec bug; the real guarantee is that agent code never spawns anything the server chose (section 8). A transient unit is outside the agent's sandbox, so its own properties must be at least as strict as the task allows (for example `InaccessiblePaths=` for the credential, C11) | State this plainly in P3-A05 and in ADR 0003's per-task table. Consider a later ADR for a polkit or D-Bus policy that limits which unit names the agent may start (Q7). **Done in #35:** see `docs/operations/agent-task-privileges.md` |
| F-3 | `restart_service` needs only the service manager over D-Bus, which the current unit already allows | No sandbox relaxation needed for restarts; the control is entirely the name checks (C4, C5) | P3-A05 records "no change" for `restart_service`. **Done in #35:** see `docs/operations/agent-task-privileges.md` |
| F-4 | The dashboard is reachable from the LAN without Access (B4, V7), and the server sees no Access assertion | Access protects only the public path | Q2 |
| F-5 | The audit table's append-only triggers are owned by the same role the application uses and that runs migrations | Triggers protect against application bugs, not a compromised server (A3) | Q5 |
| F-6 | The agent API's default body limit is 64 KB (`Api::V1::BaseController.max_body_bytes`) | The result endpoint needs an explicit limit tied to the server's output limit (V4) | P3-S04 sets `max_body_bytes` (and gzip acceptance) for results |
| F-7 | No Active Record encryption is configured yet | TOTP secrets would be stored in plaintext columns by default (C13) | Resolved by P3-S09: Active Record encryption with `FLEET_ENCRYPTION_KEY`, listed in the backup procedure's separately kept secrets (NFR-2) |

## 10. Not yet built: what later issues must deliver

All Phase 3 controls are unbuilt. This maps each to its issue. Rows marked (P) carry a proposal from this document that the issue's spec does not contain yet.

| Issue | Spec | Must deliver (threat rows) |
|---|---|---|
| #29 | P3-TASK-MODEL (P3-S01, P3-S02) | Shared catalog, lint, contract test (S1, C1, C2); closed models with no command-carrying field (section 8); bulk creation with excluded hosts (H11 (P)); batch cap; per-batch concurrency and open-task limits (D1 (P), D2 (P)) |
| #30 | P3-TASK-API (P3-S03, P3-S04) | Host-scoped poll/start/progress/result (V1); atomic claim with DB-time expiry (R1, L1 (P)); idempotent start and result, conflicting result rejected (R3, R4); output truncation and sanitisation including bidi (O2 (P)); result body limit (V4, F-6); claim-time re-validation (C14) |
| #31 | P3-TASK-CONTROLS (P3-S05, P3-S06, P3-S07) | Lease, expiry, timeout jobs, idempotent and concurrent-safe (L1–L6); cancellation semantics (L3, F6); allowlists and limits with step-up and audit (A2); cancel queued tasks on revoke, re-enroll, retire (V9 (P)); audit completeness and retention guard (A1, A4) |
| #32 | P3-DASH-CREATE (P3-S08, P3-S09) | TOTP step-up on every relevant endpoint (H1, H2); fresh code for large batches (H3 (P)); console-issued first enrolment (H4 (P)); code reuse refusal and lockout (H5 (P)); encrypted TOTP secrets (C13 (P), F-7); recovery codes (H7); form idempotency token (H10 (P)); operator-set names in targeting (H11 (P)) |
| #33 | P3-DASH-TASKS | Escaped output, including Turbo broadcasts (O1); bidi made visible (O2 (P)); safe download headers (O3 (P)); plain wording for `interrupted`, `not_run`, `lease_expired` (L2) |
| #34 | P3-AGENT-LEDGER (P3-A01, P3-A02) | Embedded catalog and local `[tasks]` config, fail-safe defaults (C1, C3); ledger with `started` before execution and no re-run (C7, R2); `acknowledged` step and `not_run` reason (L2 (P)); reconciliation of a still-running transient unit (L8 (P)); update deferral (L7); journal record of every task decision (A3 (P)) |
| #35 | P3-AGENT-EXEC (P3-A03, P3-A05) | Strict typed validation, refusal with no execution (C2); compile-time spawn API (section 8 (P)); static no-shell check scoped to non-test code (section 8); fixed environment, process groups, timeouts, bounded output (C6, C11, D4, O6); transient units and the per-task privilege table (F-1, F-2 (P)); no fault hooks in release (S7). **Built in #35**, except that the task types themselves are #36 and #37 |
| #36 | P3-AGENT-TASKS (P3-A04, P3-A06) | Both allowlists and the protected list (C4); unit-name pattern without globs, `.service` only, alias resolution against the protected list (C5, D6). Built in #36 |
| #37 | P3-AGENT-UPDATES | ADR 0016 policy, lock wait, timeout, `reboot_required` (D3); needrestart in list mode in the fixed environment (D7); transient-unit execution with the property list reviewed for real upgrades (F-1); recovered outcome (L8); no parameters (C15). **Built in #37** |
| #38 | P3-SECURITY (P3-X01, P3-X02, P3-X03) | Finalise this document; no-arbitrary-shell review note (section 8); FR-3.1/FR-3.3 bullet-to-test mapping; dependency audit; CODEOWNERS check (S2 (P)); adversarial tests (C1, C2, V1, V4, V5); crash matrix (R2, L2, L3, L8) |

## 11. Open questions for the owner

| ID | Question | Recommendation |
|---|---|---|
| Q1 | How is the **first** TOTP enrolment protected, given that Google cannot be forced to re-authenticate (H4)? | A one-time enrolment code issued from the server console, like adding the first operator |
| Q2 | Should production dashboard requests require a valid Cloudflare Access assertion, closing the LAN path around Access (V7, F-4)? This changes the documented acceptance of VPN users reaching the dashboard on the internal hostname | Keep the current acceptance for viewing, but consider requiring the assertion (or a VPN-only allowlist of source addresses) for task-creating endpoints |
| Q3 | Should a large batch (above 3 hosts) or an allowlist widening need a fresh TOTP code rather than the 5-minute window (H3)? | Yes |
| Q4 | Should batches run with a concurrency limit and halt on first failure, like agent rollouts (D1)? | Yes for `apply_package_updates` and `restart_service`, for example 1 host first, then 5 at a time |
| Q5 | Is the server-side audit log required to survive a compromised server (A3, F-5)? If so: a separate, non-owner DB role for the application, or shipping entries off the server | For the homelab, accept and rely on the per-VM journal; revisit for scale (ADR 0019) |
| Q6 | ADR 0016 says the task never restarts services. Packages' own maintainer scripts do (D7). Is "the agent never restarts services; packages may restart their own" the intended meaning? | Yes; amend ADR 0016's wording and suppress `needrestart` |
| Q7 | Run `apply_package_updates` in a transient unit outside the agent's sandbox (F-1)? And is a polkit rule limiting which units the agent may start worth a later ADR (F-2)? | Yes to the transient unit; defer the polkit rule |
| Q8 | Should revoking, re-enrolling, or retiring a host cancel its queued tasks (V9)? | Yes, audited |
| Q9 | Task signing stays rejected (ADR 0014). With S3 (GitHub account) and E2 (server VM) as the top risks, is that still the owner's view for Phase 3? A per-VM operator key would only help if it lived off the server and off GitHub | Keep rejected for Phase 3; record it as a scale-up topic |
| Q10 | FR-3.2's non-interruptible cancel interpretation (P3-S05) still awaits confirmation in ADR 0014. ADR 0014 now states it; does the owner consider P3-S05's note resolved? | Resolved: the owner confirmed it (mockup Q17); ADR 0014 and P3-S05 record it (#31) |

## 12. Residual risks accepted so far

- Anyone who holds the server, the database, or a session plus the authenticator can run every enabled catalog task, with valid parameters, on every host that enabled it (ADR 0014). The agent bounds **what** runs, not **when** or **how often**.
- TOTP is phishable in real time (ADR 0006, owner decision 2026-11-08).
- A compromised VM is authoritative about its own results (V2).
- The owner's GitHub account is a single point of control over both the server deployment and agent releases (S3, ADR 0018).
- Cloudflare, and whoever controls the owner's Cloudflare account, can impersonate the server to agents with LAN or DNS position (ADR 0024); they still get no more than a compromised server.
- Running `apply_package_updates` runs whatever the VM's configured APT sources and maintainer scripts do, as root. Debian's archive signing is the control; the agent adds none.

## 13. Keeping this document current

- Each Phase 3 PR that builds a control changes its row's status to **Built** and names the test in **Proven by**.
- A PR that adds a task type adds rows for it in 6.2 and the privilege table, and cannot merge without this document changing.
- An accepted proposal moves into the issue's spec (and an ADR where it changes a decision); the row then cites that spec.
- P3-X01 closes with every row Built, Accepted by the owner, or tracked as an issue.
