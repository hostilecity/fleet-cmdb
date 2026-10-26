# Fleet CMDB — Requirements

A configuration management database (CMDB) for homelab virtual machines (VMs), with a Ruby on Rails server, a monitoring dashboard, and a Rust agent on each VM.

This document covers all three planned phases. Build them in order. Each phase must work on its own before the next one starts.

## How to assign this work

Give the coding agent one phase at a time, plus the shared foundations in section 4. Do not ask for all three phases in a single change.

For each assigned phase, the agent must deliver:

- Working code for that phase, with migrations, tests, and seed or example data where relevant
- A short delivery note listing what was built, what was tested, and anything left incomplete
- No features from a later phase, and no features listed under Out of scope

If a requirement conflicts with an open decision in section 10, the agent should use the recommended default, note that it did so, and continue. The agent must not invent a different architecture, add arbitrary remote shell access, or reintroduce over-the-air (OTA) updating.

Requirement IDs are stable. Reference them in commits, pull requests, tests, and delivery notes — for example, `FR-1.4 heartbeat and liveness`.

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

## 2. Design principles

- **Server evaluates, agent reports.** Agents send raw, structured facts. The server decides what those facts mean.
- **Pull, do not push, to agents.** Agents initiate all connections to the server. No inbound ports are opened on VMs.
- **Least privilege by default.** An agent can only act on its own host record and its own tasks.
- **Every state change is auditable.** Enrollment, inventory changes, evaluation results, and task actions leave a record with a timestamp and an actor.
- **Idempotent reporting.** Re-sending the same report must not create duplicates or corrupt state.
- **Boring, inspectable technology.** Prefer Rails conventions, a relational database, background jobs inside the Rails stack, and a single static Rust binary for the agent.
- **Homelab scale, production discipline.** Design for tens of VMs, not thousands, but keep authentication, validation, tests, and backups at a standard that would survive real use.

## 3. Architecture

| Component | Technology | Responsibility |
|---|---|---|
| CMDB server and dashboard | Ruby on Rails | Host records, dashboard, application programming interface (API), evaluation, task dispatch, audit log |
| Database | Relational, via Rails | All persistent state; no state held only in agent or server memory |
| Agent | Rust, single binary | Enrollment, heartbeat, fact collection, task polling and execution (Phase 3) |
| Background jobs | Rails job system | Liveness transitions, Phase 2 evaluations, vulnerability matching, stale-data cleanup |

### Data flow

1. An operator creates a host record in Rails, or approves an enrollment request, and issues a per-host credential.
2. The agent on the VM sends heartbeats and reports to the Rails API over HTTPS.
3. Rails validates, stores, and derives status and findings from those reports.
4. The operator reads everything from the dashboard. In Phase 3, the operator also creates tasks there; agents poll for, run, and report back on their own tasks.

### Deployment assumptions

- The Rails server runs on one homelab machine or VM and is reachable by all agents on the local network or over a private overlay network.
- Each agent runs as a systemd service on a Linux VM.
- Time on the server is authoritative for `last_seen_at` and all audit timestamps. Agent-reported times are stored separately and never trusted for liveness.

## 4. Shared foundations — all phases

Build these in Phase 1 and reuse them unchanged in Phases 2 and 3.

### FR-S.1 Enrollment and agent identity

- Each host has one agent identity, created through an enrollment flow the operator controls.
- Enrollment issues a unique, revocable, per-host credential. Credentials are never shared between hosts.
- The server stores only a hash of each credential, never the credential itself.
- The agent stores its credential in a root-readable-only config file and sends it on every request.
- Revoking a credential immediately blocks that agent's requests and marks the host's credential as revoked in the dashboard.
- Re-enrollment replaces the old credential; the old credential stops working at that moment.

### FR-S.2 API rules

- The agent API is versioned, starting at `/api/v1`, and speaks JSON over HTTPS.
- Every request is authenticated as a specific host. An agent cannot read or write another host's data, even if it guesses an identifier.
- The server validates every field: type, length, and allowed values. Unknown fields are rejected or ignored consistently, and the choice is documented.
- Reports carry a stable report identifier and a schema version so retries are safe and future changes are detectable.
- Errors return a consistent JSON shape with a machine-readable code and a human-readable message. A failed request must never leave a half-written record.
- The server applies per-host rate limits generous enough for normal reporting but tight enough to stop a malfunctioning agent from filling the database.

### FR-S.3 Audit log

- Record at minimum: host created, enrolled, credential revoked, host edited or retired, and — in later phases — evaluation rule changes and every task action.
- Each entry records actor (operator or agent host), action, target, timestamp, and relevant before/after values for operator edits.
- Audit entries are append-only in normal use. The dashboard exposes them read-only.

### FR-S.4 Dashboard access

- The dashboard requires operator sign-in. There is no public or anonymous view of fleet data.
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

Retiring a host keeps its history and audit trail but removes it from the active fleet counts. Deleting a host outright is not offered in Phase 1.

### FR-1.2 Agent heartbeat

- The agent sends a heartbeat at a configurable interval, defaulting to 60 seconds.
- A heartbeat contains the host identity, agent version, agent uptime, and the agent's current time.
- Heartbeats are cheap: they update `last_seen_at` and liveness only. Full inventory travels in the separate report in FR-1.3.
- On failure, the agent retries with exponential backoff and jitter, caps the backoff, and keeps running. A server outage must never crash or exit the agent.

### FR-1.3 Inventory report

- The agent sends a full inventory report on startup, on a configurable interval defaulting to 15 minutes, and when a collected field materially changes.
- Required fields: hostname, operating system name and version, kernel version, architecture, central processing unit (CPU) model and core count, total and available memory, disk size and free space per mount, primary network addresses, uptime, agent version, and a boot identifier so the server can detect reboots.
- Collection must degrade gracefully: if one field cannot be read on a given VM, the report still sends, with that field null and a collection warning attached.
- The server stores the latest inventory as the host's current state and keeps dated inventory snapshots so an operator can see what changed and when.
- Submitting the same report twice produces one snapshot, not two.

### FR-1.4 Liveness

- Status is derived on the server from `last_seen_at`, never reported by the agent.
- Default thresholds, configurable by the operator: **online** if the last heartbeat is under 3 minutes old, **stale** if it is 3–15 minutes old, **offline** if older than 15 minutes.
- Status changes are visible on the dashboard without a manual refresh of the underlying data and are recorded so an operator can see when a host went offline and returned.

### FR-1.5 Dashboard — Phase 1

- **Fleet list:** every active host with name, hostname, tags, operating system, agent version, liveness status, and last seen. Sortable, searchable by name and hostname, and filterable by tag and status. Fleet counts by status appear at the top.
- **Host detail:** full current inventory, inventory history with field-level change highlighting, enrollment and credential state, and the host's audit entries.
- **Operator actions:** create or approve a host, edit name, description, notes and tags, revoke a credential, and retire a host.

### FR-1.6 Agent packaging and operation

- The agent ships as a single Rust binary plus an example config file and a systemd unit.
- Configuration covers server URL, credential, heartbeat and inventory intervals, and log level. No recompilation is needed to change any of them.
- The agent logs to the systemd journal with structured, timestamped lines, and logs each report's outcome without logging the credential.
- The agent must run for days without leaking memory, file handles, or disk.

### Phase 1 acceptance criteria

- [ ] Enrolling a new VM makes it appear in the dashboard within one heartbeat interval
- [ ] Stopping the agent moves the host through stale to offline at the configured thresholds; restarting it returns the host to online
- [ ] Inventory on the host detail page matches `hostnamectl`, memory, and disk figures read manually on the VM
- [ ] Re-sending an identical inventory report creates no duplicate snapshot
- [ ] A revoked credential receives authentication errors and cannot report, even with correct payloads
- [ ] One host's credential cannot read or modify another host's record
- [ ] Automated tests cover enrollment, heartbeat, inventory validation, liveness transitions, and credential revocation

## 6. Phase 2 — Config, CIS, package, and vulnerability reporting

Phase 2 adds two fact feeds from the same agent and two evaluations that run entirely on the server. Agents never judge their own compliance or vulnerability state.

Phase 2 starts only after Phase 1 is accepted.

### FR-2.1 Configuration reporting

- On a configurable interval, defaulting to 6 hours, and on operator request via the dashboard, the agent collects a defined set of configuration facts and sends them as structured key–value data with a schema version.
- The initial fact set must cover, where the VM exposes them: secure shell (SSH) server settings, password and login policy values, firewall enabled state, automatic updates enabled state, file permissions on a defined list of sensitive files, running and enabled services, and local user accounts with login shells.
- The fact set is defined by a versioned manifest the server publishes, so adding a fact is a server-side change plus agent support for reading it — not a new ad hoc payload per check.
- Facts the agent cannot read are reported as unreadable with a reason, never silently omitted and never guessed.
- The server stores each config report as a dated snapshot and can diff two snapshots for one host.

### FR-2.2 CIS benchmark evaluation — server side

- The server evaluates config snapshots against Center for Internet Security (CIS) benchmark rules expressed as data — rule identifier, CIS reference, title, severity, the fact it inspects, the expected value or condition, and remediation guidance text.
- Rules ship as a starter set for the Linux distributions actually used in the fleet, imported from a file the operator controls. The agent must not need an update when a rule changes.
- Each evaluation produces one result per rule per host: pass, fail, or not applicable / not readable, with the observed value that produced the result.
- The dashboard shows per-host and per-rule results, a compliance summary per host (passed / failed / not evaluated), and result history so an operator can see a failure appear and clear.
- Editing, disabling, or adding a rule re-evaluates stored snapshots without contacting agents.

### FR-2.3 Package reporting

- On the same reporting cadence as FR-2.1, the agent reports every installed package as structured data: package name, installed version, architecture, and source (the operating system's package manager).
- Support the package managers present in the fleet; detect the manager rather than assuming one. A VM whose manager is unsupported reports that state explicitly.
- The server stores the latest package set per host plus dated snapshots, and can diff package sets to show installs, removals, and version changes.

### FR-2.4 Vulnerability matching — server side

- The server matches stored package sets against vulnerability data imported by the operator or fetched from a configured advisory source: advisory identifier, affected package, affected version range, fixed version where known, severity, and a link to the advisory.
- Matching produces one finding per host, package, and advisory, with state: open, resolved (package updated or removed), or reopened.
- When a new package snapshot arrives or vulnerability data is refreshed, matching re-runs automatically in a background job. Agents are not involved.
- The dashboard shows findings per host and per package, filterable by severity, with fleet-wide counts of open findings by severity.
- Matching must handle version comparison using the package manager's own version rules. String comparison of versions is not acceptable.

### FR-2.5 Dashboard — Phase 2 additions

- Host detail gains three views: configuration (latest facts, CIS results, snapshot diff), packages (current set, snapshot diff), and vulnerabilities (open and resolved findings).
- A fleet compliance view lists every host with its CIS pass rate, open CIS failures by severity, and open vulnerability findings by severity.

### Phase 2 acceptance criteria

- [ ] A config snapshot taken before and after an SSH setting change shows the changed value in the diff and flips the related CIS rule between pass and fail
- [ ] Editing a CIS rule's expected value and re-evaluating changes results for stored snapshots with no agent contact
- [ ] A package report matches the VM's own package manager listing, with no missing or invented packages
- [ ] Importing an advisory for an installed package version creates an open finding; updating that package on the VM and re-reporting resolves it
- [ ] Unreadable facts appear as not readable with a reason in both the snapshot and the affected CIS results
- [ ] Automated tests cover config validation, CIS rule evaluation (pass, fail, not applicable), package version comparison, and vulnerability matching and resolution

## 7. Phase 3 — Remote tasks from an allowlist

Phase 3 lets an operator ask agents to perform maintenance. It is the highest-risk phase: a compromised server or a careless implementation becomes remote code execution across the fleet. The controls in this section are requirements, not suggestions.

Phase 3 starts only after Phase 2 is accepted, and the task catalog starts small — patch updates and service restart are the expected first entries.

### FR-3.1 Allowlisted task catalog — no arbitrary shell

- Tasks are chosen from a fixed catalog defined in agent code and mirrored on the server. Each catalog entry has a stable task type identifier, a plain-language name, a description of exactly what it runs, and a fixed parameter schema.
- **The server can never send a command line, shell string, script, or executable name to an agent.** It sends only a task type identifier plus parameters that validate against that type's schema.
- The agent maps the task type to its own pre-defined implementation. If the type is unknown, or any parameter fails validation, the agent refuses the task and reports the refusal.
- Adding a new task type requires a new agent release and a matching server catalog entry. It is never a dashboard-only change.
- Initial catalog, at minimum: apply operating system package updates, restart a named service (the service name validates against a server-configured allowlist of services), and re-collect inventory, config, and package reports on demand.

### FR-3.2 Task lifecycle

- An operator creates a task for one host, or for many hosts at once by tag or explicit selection. Bulk creation creates one independent task record per host so each can succeed or fail on its own.
- Task states: queued, claimed, running, succeeded, failed, timed out, cancelled, refused.
- Agents receive tasks only by polling the server, on the heartbeat path or a dedicated poll at a configurable interval. The server does not connect to agents.
- Claiming is atomic: if an agent restarts and polls again, it must never run the same task twice. Each task carries a unique identifier the agent records before execution, and a task already recorded as started is reported, not re-run.
- The agent reports progress where a task type supports it, and always reports a final result: exit status mapped to succeeded or failed, start and finish times, and captured output truncated to a server-defined limit with truncation clearly marked.
- The server sets a per-task timeout by task type. A task exceeding it is marked timed out, and the agent terminates its own over-running task and reports that it did so.
- An operator can cancel a queued or claimed task. A running task is cancelled only if its type supports safe interruption; otherwise cancellation takes effect before the next task starts, and the dashboard says so plainly.

### FR-3.3 Execution safety on the agent

- Each task type declares the privilege it needs. The agent runs tasks with the minimum privilege that works, and the delivery note for Phase 3 must state, per task type, what privilege it uses and why.
- Tasks run with a clean, fixed environment — no operator-supplied environment variables — and a fixed working directory.
- Concurrent task execution on one host is limited to one task at a time by default. A second claimed task waits or is reported as blocked, never run in parallel without the operator knowing.
- If the agent is shutting down mid-task, it reports the interruption on its next start rather than leaving the task silently in running state.

### FR-3.4 Dashboard and audit — Phase 3

- Create-task flow: choose task type, see exactly what it will do in plain language, set validated parameters, choose target hosts, confirm.
- Task list and task detail: state, target host, parameters, timeline, output, and result, filterable by host, type, and state.
- Every task creation, claim, cancellation, and result is written to the audit log with the operator who created it.
- Fleet-wide task actions show per-host progress counts — for example, 6 succeeded, 1 running, 1 failed — not just a single aggregate state.

### Phase 3 acceptance criteria

- [ ] Sending a task with an unknown type, or with a parameter outside its schema, results in a refused task and no execution on the VM — verified by attempting it against the API directly, not only through the dashboard
- [ ] No API path exists by which a caller can supply a shell string or command name; a code review note in the delivery confirms the check was performed
- [ ] Killing and restarting the agent mid-poll and mid-task never causes the same task to run twice
- [ ] Applying package updates on a test VM updates the packages, reports success with output, and the following package report reflects the new versions
- [ ] A task that exceeds its timeout is terminated on the VM and marked timed out on the server
- [ ] Cancelling a queued task means the agent never runs it
- [ ] Automated tests cover catalog validation, atomic claiming, idempotent execution, timeout, cancellation, and result reporting

## 8. Non-functional requirements

### NFR-1 Security

- All agent–server traffic uses HTTPS; the agent verifies the server certificate and does not offer a mode that disables verification.
- Dashboard sessions use secure, HTTP-only cookies, and operator passwords are stored hashed using the Rails default.
- All agent input is treated as untrusted and validated before storage or display. Inventory and output text rendered in the dashboard is escaped, so a compromised VM cannot inject markup into an operator's browser.
- Secrets — agent credentials, operator credentials, advisory source keys — never appear in logs, error messages, or task output.

### NFR-2 Reliability and data safety

- The server database is backed up by a documented, restorable procedure before Phase 1 is considered done.
- Snapshots and audit entries are retained for at least 90 days by default; any pruning is a configurable job that never prunes audit entries for tasks in Phase 3 within that window.
- A failed background job retries with backoff and surfaces persistent failures somewhere an operator will see them, rather than failing silently.

### NFR-3 Performance and scale

- The system stays responsive with 50 hosts reporting on the default intervals: dashboard fleet list loads in under 2 seconds on the homelab server, and heartbeat handling does not degrade as snapshots accumulate.
- Snapshot growth is bounded by retention settings, not by manual database cleanup.

### NFR-4 Observability and operability

- Server and agent both emit structured logs with timestamps, host identity where relevant, and request or report identifiers that let one report be traced end to end.
- A simple health endpoint on the server reports application and database status for monitoring.
- Installation is documented well enough that the owner can set up the server and enroll a new VM from the documentation alone: server setup, agent install, enrollment, upgrade, and uninstall.

### NFR-5 Maintainability

- The agent API is covered by contract-style tests shared in spirit across phases: a payload accepted in Phase 1 stays readable after Phase 2 and 3 changes, or its schema version increments with a migration path.
- Agent and server versions are independent. The server accepts reports from the previous agent release, or returns a clear minimum-version error the agent logs plainly.

## 9. Build order and definition of done

1. Shared foundations (section 4) and Phase 1 — enroll, heartbeat, inventory, liveness, dashboard.
2. Phase 2 — config facts, CIS evaluation, package reporting, vulnerability matching.
3. Phase 3 — task catalog, lifecycle, dashboard, with the safety checks in FR-3.1 and FR-3.3 verified last and most carefully.

A phase is done only when all of these hold:

- Every acceptance criterion for the phase passes, and the delivery note maps each criterion to the test or manual check that proved it
- Automated tests for the phase pass in a clean run, and no earlier phase's tests were broken
- Database migrations run forward cleanly from the previous phase's state
- Documentation is updated: setup, configuration, and any new operator workflow
- No out-of-scope feature was added, and any recommended default taken from section 10 is named in the delivery note

## 10. Open decisions for the owner

The coding agent should use the recommended default unless the owner decides otherwise before that phase starts.

| Decision | Needed by | Recommended default |
|---|---|---|
| Which Linux distributions run in the fleet | Phase 1 | Build and test on the fleet's actual distributions; collect inventory generically |
| Package managers to support | Phase 2 | Support the managers present on the fleet's distributions; detect automatically |
| Source of CIS rules | Phase 2 | Operator-imported rule file covering the fleet's distributions; no live external dependency |
| Source of vulnerability data | Phase 2 | Operator-imported or configured advisory feed matched on package name and version; findings always link to the source advisory |
| Which services may be restarted remotely | Phase 3 | Empty allowlist until the owner names services; the restart task refuses everything before then |
| May package updates reboot a VM if required | Phase 3 | No — the update task reports that a reboot is needed and never reboots on its own |
| Dashboard hosting and TLS certificate source | Phase 1 | Private network access only, with a certificate the agents trust; no public exposure |
| Snapshot and audit retention period | Phase 1 | 90 days, configurable |

