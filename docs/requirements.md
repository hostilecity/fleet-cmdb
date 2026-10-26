# Fleet CMDB — Requirements

A configuration management database (CMDB) for homelab virtual machines (VMs), with a Ruby on Rails server, a monitoring dashboard, and a Rust agent on each VM.

This document is the product source of truth: it defines the requirement IDs (`FR-*`, `NFR-*`, `AC-*`) that issues, specs, and pull requests cite. Decisions are recorded as ADRs in [`docs/decisions/`](decisions/README.md) (referenced here as `DEC-nn`). How work is run (issues, specs, pull requests, delivery notes, phase gates) is in [`AGENTS.md`](../AGENTS.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md); implementation details are in [`docs/backlog/specs/`](backlog/specs/).

## 1. Product summary

The system answers three questions about a small fleet of homelab VMs:

1. What machines exist, what are they running, and are they alive? — Phase 1
2. Are they configured safely, and are their packages vulnerable? — Phase 2
3. Can an operator run a small set of approved maintenance actions on them remotely, with a full audit trail? — Phase 3

The Rails application is the system of record. It stores inventory, evaluates policy, and presents the dashboard. The Rust agent is deliberately thin: it collects facts and, in Phase 3, executes only allowlisted tasks. Evaluation logic lives on the server so benchmark rules and vulnerability data can change without redeploying agents.

### Out of scope

- OTA firmware or operating system image updates, A/B partitions, signed firmware bundles, and any signer tool — removed from scope; do not build them
- Support for physical or embedded devices, including ESP32 — not part of this project
- Arbitrary shell commands sent from the server to agents
- Container orchestration, VM provisioning, or hypervisor management
- Multi-tenancy, public sign-up, or use as a commercial software-as-a-service product
- Agent support for non-Linux operating systems in Phases 1–3, unless the owner approves it later
- Automatic remediation of CIS or vulnerability findings — Phase 2 reports and scores findings; it does not fix them
- Agent self-update. Upgrading an agent is a manual binary replacement documented in NFR-4.

## 2. Design principles

- **Server evaluates, agent reports.** Agents send raw, structured facts. The server decides what those facts mean.
- **Pull, do not push, to agents.** Agents initiate all connections to the server. No inbound ports are opened on VMs.
- **Least privilege by default.** An agent can only act on its own host record and its own tasks.
- **Every state change is auditable.** Enrollment, inventory changes, evaluation results, and task actions leave a record with a timestamp and an actor. High-volume derived events (heartbeats, liveness transitions) are recorded in their own tables, not the audit log.
- **Idempotent reporting.** Re-sending the same report must not create duplicates or corrupt state.
- **Boring, inspectable technology.** Prefer Rails conventions, a relational database, background jobs inside the Rails stack, and a single static Rust binary for the agent.
- **Homelab scale, production discipline.** Design for tens of VMs, not thousands, but keep authentication, validation, tests, and backups at a standard that would survive real use.

## 3. Architecture

| Component | Technology | Responsibility |
|---|---|---|
| CMDB server and dashboard | Ruby on Rails | Host records, dashboard, application programming interface (API), evaluation, task dispatch, audit log |
| Database | Relational, via Rails | All persistent state; no state held only in agent or server memory |
| Agent | Rust, single static binary | Enrollment, heartbeat, fact collection, task polling and execution (Phase 3) |
| Background jobs | Rails job system | Liveness transitions, Phase 2 evaluations, vulnerability matching, stale-data cleanup |

Stack (decided, DEC-02): Ruby 3.4 and Rails 8.1, PostgreSQL, Solid Queue and Solid Cable, Hotwire (Turbo and Stimulus) for the dashboard, RSpec for server tests. The agent builds as a static `musl` binary with `rustls`.

### Repository layout

```
docs/
  requirements.md
  backlog/        # issues.yml (short issue stubs) and specs/ (implementation details; source of truth)
  mockups/
  decisions/      # architecture decision records, one per DEC-nn
  api/            # agent API spec, JSON Schemas, example payloads
cmdb/             # Rails server and dashboard
agent/            # Rust agent
```

### Data flow

1. An operator creates a host record, which issues a one-time enrollment token (FR-S.1). The agent redeems the token for a per-host credential.
2. The agent on the VM sends heartbeats and reports to the Rails API over HTTPS.
3. Rails validates, stores, and derives status and findings from those reports.
4. The operator reads everything from the dashboard. In Phase 3, the operator also creates tasks there; agents poll for, run, and report back on their own tasks.

### Deployment assumptions

- The Rails server runs in Docker on one homelab machine and is reachable by agents on the local network. (decided, DEC-05)
- The dashboard is published to the operator through a Cloudflare tunnel, which terminates TLS, with Cloudflare Access in front of it. (decided, DEC-05)
- The **agent API is private**: it is served only on a separate hostname that resolves to a private address, with its own Let's Encrypt certificate (DNS-01 through Cloudflare), and is never routed through the tunnel. Rails enforces this with host-based route constraints, so dashboard routes answer only on the dashboard hostname and `/api/v1` only on the agent hostname. (decided, DEC-05)
- Each agent runs as a systemd service on a Debian VM; the fleet profile is Debian 13 on x86_64 with systemd and dpkg/apt. Other distributions and architectures are out of scope until the owner adds them. (decided, DEC-01)
- Time on the server is authoritative for `last_seen_at` and all audit timestamps. Agent-reported times are stored separately and never trusted for liveness.

## 4. Shared foundations — all phases

Build these in Phase 1 and reuse them unchanged in Phases 2 and 3.

### FR-S.1 Enrollment and agent identity

- Each host has one agent identity, created through an enrollment flow the operator controls.
- Enrollment is initiated by the operator: creating a host record issues a single-use enrollment token that expires (default 24 hours). The agent redeems the token once for its permanent credential. There is no unauthenticated self-registration. (decided, DEC-04)
- Enrollment issues a unique, revocable, per-host credential. Credentials are never shared between hosts.
- The server stores only a hash of each credential, never the credential itself. Credentials are long random values, so a keyed or plain SHA-256 digest with constant-time comparison is appropriate; they must not be stored in plaintext (for example with Rails `has_secure_token`) and need not use a password hash. Each credential carries a non-secret identifier so lookup does not require scanning.
- The agent stores its credential in a configuration file readable only by the agent's service account (mode `0600`) and sends it on every request.
- Revoking a credential immediately blocks that agent's requests and marks the host's credential as revoked in the dashboard.
- Re-enrollment replaces the old credential. The operator triggers it by issuing a new enrollment token for the existing host; the old credential stops working at the moment the new token is redeemed.
- Where the agent can identify the machine (for example `machine-id`), the server warns when the same credential is used from a machine that does not match the host's recorded identity, which catches cloned VMs.

### FR-S.2 API rules

- The agent API is versioned, starting at `/api/v1`, and speaks JSON over HTTPS.
- The agent API is reachable only on the private agent hostname; a request to `/api/v1` on the dashboard hostname is rejected, and a dashboard route on the agent hostname is rejected. (decided, DEC-05)
- Every request is authenticated as a specific host. An agent cannot read or write another host's data, even if it guesses an identifier.
- The server validates every field: type, length, and allowed values. Unknown fields are ignored and logged; unknown values for enumerated fields and wrong types are rejected. (decided, DEC-08)
- Reports carry a stable report identifier and a schema version (an integer) so retries are safe and future changes are detectable.
- Errors return a consistent JSON shape with a machine-readable code and a human-readable message. A failed request must never leave a half-written record.
- The server applies per-host rate limits generous enough for normal reporting but tight enough to stop a malfunctioning agent from filling the database. Request bodies have a maximum size per endpoint.
- When an agent is older than the server's supported minimum, the server returns a dedicated error code (decided: HTTP 426, code `agent_version_unsupported`) that the agent logs plainly. (decided, DEC-08)

### FR-S.3 Audit log

- Record at minimum: host created, enrolled, credential revoked, host edited or retired, and — in later phases — evaluation rule changes and every task action.
- Each entry records actor (operator or agent host), action, target, timestamp, and relevant before/after values for operator edits.
- Audit entries are append-only in normal use, and the application provides no update or delete path. The dashboard exposes them read-only.
- Audit retention is independent of snapshot retention (NFR-2): audit entries are not pruned by default.

### FR-S.4 Dashboard access

- The dashboard requires operator sign-in. There is no public or anonymous view of fleet data.
- Operators sign in with Google OAuth against an allowlist of operator email addresses held by the server; there are no application passwords and no public sign-up. The first operator is added to the allowlist from the command line. An operator is a user record keyed by their Google account, so a second operator is an additional allowlist entry. (decided, DEC-06)
- A single-operator setup is acceptable for Phases 1–3, but the design must not hard-code one user in a way that blocks adding a second operator later.
- All dashboard forms validate input and show errors in place. Destructive actions — retire host, revoke credential, cancel task — require explicit confirmation.

## 5. Phase 1 — CMDB and fleet inventory

Phase 1 is complete when an operator can enroll a VM, see it appear in the dashboard within one heartbeat interval, watch it go stale and then offline when the agent stops, and trust that the inventory shown matches the VM.

### FR-1.1 Host record

Each host record stores at minimum:

- Display name and hostname
- Description and free-form notes, editable by the operator
- Tags, editable by the operator — for example `web`, `media`, `lab` — usable as dashboard filters
- Enrollment state: pending, active, revoked, or retired
- First seen and last seen timestamps
- Agent version and agent schema version
- Current liveness status, as defined in FR-1.4

Enrollment state transitions:

| From | To | Trigger |
|---|---|---|
| (none) | pending | Operator creates the host record |
| pending | active | Agent redeems the enrollment token |
| active | revoked | Operator revokes the credential |
| revoked | pending | Operator issues a new enrollment token (re-enrollment) |
| active | pending | Operator issues a new enrollment token; the old credential keeps working until the new token is redeemed |
| any | retired | Operator retires the host; retiring also revokes the credential |

Retired is terminal in Phase 1. Liveness applies to active hosts only; pending, revoked, and retired hosts show their enrollment state instead of a liveness status. Fleet counts cover active hosts by liveness status and show pending and revoked counts separately.

Retiring a host keeps its history and audit trail but removes it from the active fleet counts. Deleting a host outright is not offered in Phase 1.

### FR-1.2 Agent heartbeat

- The agent sends a heartbeat at a configurable interval, defaulting to 60 seconds, and sends the first heartbeat immediately on start.
- A heartbeat contains the host identity, agent version, agent uptime, and the agent's current time.
- Heartbeats are cheap: they update `last_seen_at` and liveness only. Full inventory travels in the separate report in FR-1.3. Heartbeats do not write audit entries.
- The heartbeat response carries the server time and an extensible envelope for future server-to-agent signals. In Phase 1 the envelope is empty of actions. (decided, DEC-08)
- On failure, the agent retries with exponential backoff and jitter, caps the backoff, and keeps running. A server outage must never crash or exit the agent. The agent does not queue or replay missed heartbeats or reports; it sends current state once the server is reachable again.

### FR-1.3 Inventory report

- The agent sends a full inventory report on startup, on a configurable interval defaulting to 15 minutes, and when a stable field changes (see below).
- Required fields: hostname, operating system name and version, kernel version, architecture, central processing unit (CPU) model and core count, total and available memory, disk size and free space per mount, primary network addresses, uptime, agent version, and a boot identifier so the server can detect reboots. The report also carries the machine identifier where readable.
- Fields are classed as **stable** (hostname, OS, kernel, architecture, CPU, total memory, disk size and mount list, network addresses, boot identifier, machine identifier, agent version) or **volatile** (available memory, free disk space, uptime). Only stable-field changes trigger an extra report and create a new snapshot. Volatile values update the host's current state on every report. (decided, DEC-07)
- Collection must degrade gracefully: if one field cannot be read on a given VM, the report still sends, with that field null and a collection warning attached.
- The server stores the latest inventory as the host's current state and keeps dated inventory snapshots so an operator can see what changed and when.
- Idempotency has two layers: a retried report (same report identifier) is discarded as a duplicate, and a new report whose stable fields are unchanged does not create a new snapshot.

### FR-1.4 Liveness

- Status is derived on the server from `last_seen_at`, never reported by the agent.
- Default thresholds, configurable by the operator: **online** if the last heartbeat is under 3 minutes old, **stale** if it is 3–15 minutes old, **offline** if older than 15 minutes.
- A recurring server job evaluates liveness at least every 60 seconds.
- The dashboard updates a host's status without a manual page reload, within 30 seconds of the transition being recorded. (proposed)
- Every status change is recorded in a host status history table (not the audit log) so an operator can see when a host went offline and returned.

### FR-1.5 Dashboard — Phase 1

- **Fleet list:** every active host with name, hostname, tags, operating system, agent version, liveness status, and last seen. Sortable, searchable by name and hostname, and filterable by tag and status. Fleet counts by status appear at the top.
- **Host detail:** full current inventory, inventory history with field-level change highlighting, enrollment and credential state, status history, and the host's audit entries.
- **Operator actions:** create or approve a host, edit name, description, notes and tags, revoke a credential, issue a new enrollment token, and retire a host.

### FR-1.6 Agent packaging and operation

- The agent ships as a single static Rust binary plus an example config file and a systemd unit.
- Configuration covers server URL, credential, heartbeat and inventory intervals, log level, and an optional path to an additional certificate authority bundle for servers using a private certificate authority. There is no option to disable certificate verification. No recompilation is needed to change any of these.
- The agent keeps persistent state (for example the last boot identifier and, in Phase 3, task records) in a dedicated state directory owned by its service account. Losing the directory must not break enrollment.
- The agent runs as a systemd service under the privilege model chosen in DEC-03. The unit file applies systemd sandboxing appropriate to that model.
- The agent logs to the systemd journal with structured, timestamped lines, and logs each report's outcome without logging the credential.
- The agent must run for days without leaking memory, file handles, or disk.

### Phase 1 acceptance criteria

- [ ] **AC-1.1** Enrolling a new VM makes it appear in the dashboard within one heartbeat interval
- [ ] **AC-1.2** Stopping the agent moves the host through stale to offline at the configured thresholds; restarting it returns the host to online
- [ ] **AC-1.3** Inventory on the host detail page matches `hostnamectl`, memory, and disk figures read manually on the VM
- [ ] **AC-1.4** Re-sending an identical inventory report creates no duplicate snapshot
- [ ] **AC-1.5** A revoked credential receives authentication errors and cannot report, even with correct payloads
- [ ] **AC-1.6** One host's credential cannot read or modify another host's record
- [ ] **AC-1.7** Automated tests cover enrollment, heartbeat, inventory validation, liveness transitions, and credential revocation

## 6. Phase 2 — Config, CIS, package, and vulnerability reporting

Phase 2 adds two fact feeds from the same agent and two evaluations that run entirely on the server. Agents never judge their own compliance or vulnerability state.

Phase 2 starts only after Phase 1 is accepted.

### FR-2.1 Configuration reporting

- On a configurable interval, defaulting to 6 hours, and on operator request via the dashboard, the agent collects a defined set of configuration facts and sends them as structured key–value data with a schema version.
- On-demand collection works without a general task system: the dashboard sets a "report requested" flag on the host, the agent sees it in the next heartbeat response, and collects and reports once. Phase 3's re-collect task reuses this mechanism. (decided, DEC-13)
- The initial fact set must cover, where the VM exposes them: secure shell (SSH) server settings, password and login policy values, firewall enabled state, automatic updates enabled state, file permissions on a defined list of sensitive files, running and enabled services, and local user accounts with login shells.
- The fact set is defined by a versioned manifest the server publishes, so adding a fact is a server-side change plus agent support for reading it — not a new ad hoc payload per check.
- Facts the agent cannot read are reported as unreadable with a reason, never silently omitted and never guessed.
- The server stores each config report as a dated snapshot, creates a new snapshot only when facts change, and can diff two snapshots for one host.

### FR-2.2 CIS benchmark evaluation — server side

- The server evaluates config snapshots against Center for Internet Security (CIS) benchmark rules expressed as data — rule identifier, CIS reference, title, severity, applicability (which distributions and versions the rule applies to), the fact it inspects, the expected value or condition, and remediation guidance text. Conditions use a small declarative format with no code evaluation. (DEC-12)
- Rules ship as a starter set for the Linux distributions actually used in the fleet, imported from a file the operator controls. The agent must not need an update when a rule changes. The content of the starter set must respect CIS licensing; see DEC-10.
- Each evaluation produces one result per rule per host: pass, fail, not applicable, or not readable, with the observed value that produced the result.
- Rules are versioned. Editing a rule creates a new version, and each result records the rule version that produced it, so history is never rewritten.
- The dashboard shows per-host and per-rule results, a compliance summary per host (passed / failed / not evaluated), and result history so an operator can see a failure appear and clear.
- Editing, disabling, or adding a rule re-evaluates each host's latest config snapshot without contacting agents.

### FR-2.3 Package reporting

- On the same reporting cadence as FR-2.1, the agent reports every installed package as structured data: package name, installed version (including any epoch), architecture, the package manager it came from, and the name of the source package where the package manager records one.
- Support the package managers present in the fleet; detect the manager rather than assuming one. A VM whose manager is unsupported reports that state explicitly.
- The server stores the latest package set per host plus dated snapshots (new snapshot only on change), and can diff package sets to show installs, removals, and version changes.

### FR-2.4 Vulnerability matching — server side

- The server matches stored package sets against vulnerability data imported by the operator or fetched from a configured advisory source: advisory identifier, affected package, affected version range, fixed version where known, severity, and a link to the advisory. Advisories are scoped to a distribution release, and matching uses the host's distribution and release from its inventory and the source package name where the feed uses it. (DEC-11)
- Matching produces one finding per host, package, and advisory, with state: open, resolved (package updated or removed), or reopened.
- When a new package snapshot arrives or vulnerability data is refreshed, matching re-runs automatically in a background job. Agents are not involved.
- The dashboard shows findings per host and per package, filterable by severity, with fleet-wide counts of open findings by severity.
- Matching must handle version comparison using the package manager's own version rules. String comparison of versions is not acceptable.

### FR-2.5 Dashboard — Phase 2 additions

- Host detail gains three views: configuration (latest facts, CIS results, snapshot diff), packages (current set, snapshot diff), and vulnerabilities (open and resolved findings).
- A fleet compliance view lists every host with its CIS pass rate, open CIS failures by severity, and open vulnerability findings by severity.

### Phase 2 acceptance criteria

- [ ] **AC-2.1** A config snapshot taken before and after an SSH setting change shows the changed value in the diff and flips the related CIS rule between pass and fail
- [ ] **AC-2.2** Editing a CIS rule's expected value and re-evaluating changes results for each host's latest snapshot with no agent contact
- [ ] **AC-2.3** A package report matches the VM's own package manager listing, with no missing or invented packages
- [ ] **AC-2.4** Importing an advisory for an installed package version creates an open finding; updating that package on the VM and re-reporting resolves it
- [ ] **AC-2.5** Unreadable facts appear as not readable with a reason in both the snapshot and the affected CIS results
- [ ] **AC-2.6** Automated tests cover config validation, CIS rule evaluation (pass, fail, not applicable), package version comparison, and vulnerability matching and resolution

## 7. Phase 3 — Remote tasks from an allowlist

Phase 3 lets an operator ask agents to perform maintenance. It is the highest-risk phase: a compromised server or a careless implementation becomes remote code execution across the fleet. The controls in this section are requirements, not suggestions.

Phase 3 starts only after Phase 2 is accepted, and the task catalog starts small — patch updates and service restart are the expected first entries.

### FR-3.1 Allowlisted task catalog — no arbitrary shell

- Tasks are chosen from a fixed catalog defined in agent code and mirrored on the server. Each catalog entry has a stable task type identifier, a plain-language name, a description of exactly what it runs, and a fixed parameter schema. The server's mirror and the agent's catalog are checked against one shared catalog definition file in tests, so they cannot drift.
- **The server can never send a command line, shell string, script, or executable name to an agent.** It sends only a task type identifier plus parameters that validate against that type's schema.
- The agent maps the task type to its own pre-defined implementation. If the type is unknown, or any parameter fails validation, the agent refuses the task and reports the refusal.
- Adding a new task type requires a new agent release and a matching server catalog entry. It is never a dashboard-only change.
- The agent reports the task types and catalog version it supports, and the server offers only supported types for each host.
- Initial catalog, at minimum: apply operating system package updates, restart a named service, and re-collect inventory, config, and package reports on demand.
- The service name for restart validates against a server-configured allowlist **and** an allowlist in the agent's own local configuration; the agent refuses a restart unless both permit it. The agent's own unit and the SSH service are refused unless the owner explicitly allows them (DEC-15).

### FR-3.2 Task lifecycle

- An operator creates a task for one host, or for many hosts at once by tag or explicit selection. Bulk creation creates one independent task record per host so each can succeed or fail on its own.
- Task states: queued, claimed, running, succeeded, failed, timed out, cancelled, refused, expired.
  - A task that cannot start because another is running stays claimed or queued; there is no separate "blocked" state. An interrupted task ends as failed with the reason `interrupted`.
- Every task has an expiry time (default 24 hours, configurable per task type). A task still queued at expiry becomes expired and is never delivered, so a host that returns after a long outage does not suddenly run stale instructions.
- A claim is a lease. If a claimed task shows no progress before the lease runs out, the server returns it to queued (if the agent never started it) or marks it failed with reason `lease_expired` (if the agent reported that it started).
- Agents receive tasks only by polling the server, on the heartbeat path or a dedicated poll at a configurable interval. The server does not connect to agents.
- Claiming is atomic: if an agent restarts and polls again, it must never run the same task twice. Each task carries a unique identifier the agent records before execution, and a task already recorded as started is reported, not re-run.
- The agent reports progress where a task type supports it, and always reports a final result: exit status mapped to succeeded or failed, start and finish times, and captured output truncated to a server-defined limit with truncation clearly marked.
- The server sets a per-task timeout by task type. A task exceeding it is marked timed out, and the agent terminates its own over-running task and reports that it did so.
- An operator can cancel a queued or claimed task. A running task is cancelled only if its type supports safe interruption; otherwise the task runs to completion, anything further in the same batch is not started, and the dashboard says so plainly. (decided, DEC-14)

### FR-3.3 Execution safety on the agent

- Each task type declares the privilege it needs. The agent runs tasks with the minimum privilege that works, and the delivery note for Phase 3 must state, per task type, what privilege it uses and why.
- Tasks run with a clean, fixed environment — no operator-supplied environment variables — and a fixed working directory. Non-interactive behaviour is set by the agent, not the server.
- Concurrent task execution on one host is limited to one task at a time by default. A second claimed task waits, never runs in parallel without the operator knowing.
- If the agent is shutting down mid-task, it reports the interruption on its next start rather than leaving the task silently in running state.
- Task output is treated as untrusted text: it is truncated, stored, and rendered escaped. Tasks never receive secrets in their environment or arguments, so there are none to leak into output.

### FR-3.4 Dashboard and audit — Phase 3

- Create-task flow: choose task type, see exactly what it will do in plain language, set validated parameters, choose target hosts, confirm.
- Creating or cancelling a task, and changing task allowlists, requires a recent second factor (a passkey or TOTP code enrolled in the application, independent of Google, because Google sign-in cannot be forced to re-authenticate). The check is enforced on the server for every relevant endpoint, and a hijacked operator session is otherwise one click from fleet-wide execution. (decided, DEC-06, DEC-14)
- Task list and task detail: state, target host, parameters, timeline, output, and result, filterable by host, type, and state.
- Every task creation, claim, cancellation, expiry, and result is written to the audit log with the operator who created it.
- Fleet-wide task actions show per-host progress counts — for example, 6 succeeded, 1 running, 1 failed — not just a single aggregate state.

### Phase 3 acceptance criteria

- [ ] **AC-3.1** Sending a task with an unknown type, or with a parameter outside its schema, results in a refused task and no execution on the VM — verified by attempting it against the API directly, not only through the dashboard
- [ ] **AC-3.2** No API path exists by which a caller can supply a shell string or command name; a code review note in the delivery confirms the check was performed
- [ ] **AC-3.3** Killing and restarting the agent mid-poll and mid-task never causes the same task to run twice
- [ ] **AC-3.4** Applying package updates on a test VM updates the packages, reports success with output, and the following package report reflects the new versions
- [ ] **AC-3.5** A task that exceeds its timeout is terminated on the VM and marked timed out on the server
- [ ] **AC-3.6** Cancelling a queued task means the agent never runs it
- [ ] **AC-3.7** Automated tests cover catalog validation, atomic claiming, idempotent execution, timeout, cancellation, and result reporting
- [ ] **AC-3.8** A task left queued past its expiry is never delivered to a returning agent
- [ ] **AC-3.9** The agent refuses to restart a service that is on the server allowlist but absent from its own local allowlist

## 8. Non-functional requirements

### NFR-1 Security

- All agent–server traffic uses HTTPS; the agent verifies the server certificate and does not offer a mode that disables verification.
- Dashboard sessions use secure, HTTP-only cookies. The OAuth flow validates `state` and the ID token, and only verified email addresses on the allowlist can sign in. The dashboard sends a restrictive Content Security Policy.
- All agent input is treated as untrusted and validated before storage or display. Inventory and output text rendered in the dashboard is escaped, so a compromised VM cannot inject markup into an operator's browser.
- Secrets — agent credentials, enrollment tokens, operator credentials, advisory source keys — never appear in logs or error messages. Agent credentials and enrollment tokens are shown to the operator at most once.

### NFR-2 Reliability and data safety

- The server database is backed up by a documented, restorable procedure before Phase 1 is considered done. The procedure also covers the Rails master key and any private certificate authority material, without which a restored database is unusable. The restore is tested.
- Snapshots and host status history are retained for at least 90 days by default (DEC-07); audit entries follow FR-S.3 and are not pruned by default. Pruning is a configurable job.
- A failed background job retries with backoff and surfaces persistent failures somewhere an operator will see them, rather than failing silently.

### NFR-3 Performance and scale

- The system stays responsive with 50 hosts reporting on the default intervals: dashboard fleet list loads in under 2 seconds on the homelab server, and heartbeat handling stays under 200 ms at the 95th percentile and does not degrade as snapshots accumulate. (proposed figure)
- Snapshot growth is bounded by retention settings, not by manual database cleanup.

### NFR-4 Observability and operability

- Server and agent both emit structured logs with timestamps, host identity where relevant, and request or report identifiers that let one report be traced end to end.
- A simple health endpoint on the server reports application and database status for monitoring.
- Installation is documented well enough that the owner can set up the server and enroll a new VM from the documentation alone: server setup, agent install, enrollment, upgrade, and uninstall.
- Continuous integration runs server and agent tests and linting on every pull request, and builds release agent binaries for the fleet's architectures.

### NFR-5 Maintainability

- The agent API is covered by contract-style tests shared in spirit across phases: a payload accepted in Phase 1 stays readable after Phase 2 and 3 changes, or its schema version increments with a migration path. Example payloads and JSON Schemas live in one place that both the server and agent tests consume.
- Agent and server versions are independent. The server accepts reports from the previous agent release, or returns the minimum-version error from FR-S.2 that the agent logs plainly.

## 9. Build order and definition of done

0. Phase 0 — repository scaffolding, continuous integration, and the API contract workspace (the decisions are already recorded as ADRs).
1. Shared foundations (section 4) and Phase 1 — enroll, heartbeat, inventory, liveness, dashboard.
2. Phase 2 — config facts, CIS evaluation, package reporting, vulnerability matching.
3. Phase 3 — task catalog, lifecycle, dashboard, with the safety checks in FR-3.1 and FR-3.3 verified last and most carefully.

A phase is done only when all of these hold:

- Every acceptance criterion for the phase passes, and the delivery note maps each criterion to the test or manual check that proved it
- Automated tests for the phase pass in a clean run, and no earlier phase's tests were broken
- Database migrations run forward cleanly from the previous phase's state
- Documentation is updated: setup, configuration, and any new operator workflow
- No out-of-scope feature was added, and any recommended default taken instead of a decision is named in the delivery note

## 10. Decisions and traceability

- All sixteen decisions (`DEC-01` to `DEC-16`) are recorded as ADRs; see the index in [`docs/decisions/README.md`](decisions/README.md). To change one, add an ADR that supersedes it.
- Every `FR-*`, `NFR-*`, and `AC-*` ID in this document is covered by at least one issue in [`docs/backlog/issues.yml`](backlog/issues.yml), and every `DEC-*` has an ADR. `ruby docs/backlog/import.rb check` verifies both.
