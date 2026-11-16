# Phase 3 acceptance runbook (P3-ACCEPT)

For the owner, to run the Phase 3 acceptance ([P3-ACCEPT](../backlog/specs/p3-accept.md), issue #39) on a **disposable** Debian 13 VM and record the evidence. Each acceptance criterion says what CI already proves, the steps that need a person, what to look at, what counts as a pass, and what to save. The delivery note's AC-to-proof table (in the pull request that added this file, and then on #39) has a placeholder for each item saved here.

The steps change the VM (test packages, a test service, a package left half-configured on purpose, agent kills). Use a VM you will throw away, never one that serves anything.

Names used below: the VM is `vm-p3.example.lan`, the dashboard `https://fleet.example.com`, the server container `fleet-cmdb`. Replace them with yours. "Code" means a 6-digit code from your authenticator app.

## 0. Before you start

1. **Server:** deployed from `main` at or after the commit this runbook was checked against (`78047da`), through the Deploy workflow. **Check:** `/health` is healthy apart from `backup` (no backups yet, #138).
2. **Agent release with Phase 3 in it.** The only published release, `agent-v0.1.0`, predates every Phase 3 agent change (#34 to #37), so it implements no task type. Cut a new release from the same `main` commit with the Agent release workflow ([docs/releases.md](../releases.md)), for example `0.2.0`, and import it. **Check:** the Agents page lists it.
3. **The VM:** a fresh Debian 13 VM from your template, with working Debian APT sources (`apt-get update` must succeed: the task runs it with `--error-on=any`). Install the agent from the dashboard's install page with the new release ([install-agent.md](install-agent.md)) and approve it. **Check:** the host is Online, and `fleet-agent --version` on the VM prints the new release.
4. **Your second factor:** set up under **Settings > Your second factor**.
5. **The test service** for restarts, on the VM as root. Its start takes 20 seconds, long enough to kill the agent in the middle of a restart:

   ```sh
   cat > /etc/systemd/system/p3-demo.service <<'EOF'
   [Unit]
   Description=Phase 3 acceptance test service

   [Service]
   ExecStartPre=/bin/sleep 20
   ExecStart=/bin/sleep infinity
   EOF
   systemctl daemon-reload && systemctl start p3-demo
   ```

6. **Turn the task types on** for the VM ([fleet-operations.md](fleet-operations.md#turn-task-types-on-for-a-vm)), in `/etc/fleet-agent/config.toml`:

   ```toml
   [tasks]
   enabled = ["refresh_reports", "restart_service", "apply_package_updates"]
   allowed_services = ["p3-demo.service"]
   ```

   Then `fleet-agent check-config && systemctl restart fleet-agent`. In **Settings > Tasks**, add `p3-demo.service` for every host. **Check:** the host's **Tasks** tab lists the three types and `p3-demo.service`.
7. **Test packages** for package updates: copy `agent/scripts/vm-test-packages.sh` from the repository to the VM (`scp agent/scripts/vm-test-packages.sh root@vm-p3.example.lan:/root/`). It builds tiny `.deb` packages and a local repository (the same scaffolding the CI VM test uses); it needs nothing beyond Debian's `dpkg-deb`.
8. **Two helpers.** On the VM, to see what the ledger recorded for one task:

   ```sh
   p3_ledger() { grep -F "$1" /var/lib/fleet-agent/task-ledger.jsonl | grep -o '"step":"[a-z_]*"'; }
   ```

   On the server VM, to find the id the agent logs for a task (the task page shows the number in its URL, the agent logs the UUID):

   ```sh
   p3_uuid() { docker exec fleet-cmdb bin/rails runner "puts Task.find($1).uuid"; }
   ```

9. **Evidence folder:** one folder per criterion (`p3-evidence/AC-3.1/`, ...). Save screenshots of the dashboard pages named below, and command output as text files.

**Agent restarts:** the agent's unit gives up after 4 starts within 5 minutes and then starts its rollback and recovery units (ADR 0030). The kill steps below each cost one start. Leave 5 minutes between kill steps. If `systemctl status fleet-agent` says `start-limit-hit`, run `systemctl reset-failed fleet-agent && systemctl start fleet-agent`, check that `systemctl is-active fleet-agent-recovery` says `inactive`, and go on.

## 1. What CI already proves

Each run below is on `main` at `78047da` (or, for the VM tests, at `26e5ba9`, after which nothing under `agent/` changed). Before you accept, open the same workflows for the commit you accept and check that they are green.

| Workflow and job | Run | Proves |
|---|---|---|
| Server CI, `bin/ci` | [43971294097](https://github.com/hostilecity/fleet-cmdb/actions/runs/43971294097) | The whole server suite, Phases 1 to 3, at 100% line coverage, plus RuboCop, Brakeman, bundler-audit, importmap audit. `bin/setup` builds the test database from empty (`db:prepare`). Includes every server spec named below |
| Server CI, dpkg corpus on Debian 13 | same run | Package version comparison against Debian's own `dpkg` (Phase 2) |
| Agent CI, fmt, clippy, test | [43971293954](https://github.com/hostilecity/fleet-cmdb/actions/runs/43971293954) | The whole agent suite, Phases 1 to 3, and `scripts/check-task-spawns.sh` with its `--self-test` ("No shell in the task module") |
| Agent CI, Sandbox smoke test | same run | `scripts/sandbox-smoke.sh` (the reports under the real unit), `scripts/task-privilege-smoke.sh` (9 `privilege_smoke_*` tests: each privilege level under the unit's sandbox, `restart_service` restarting a throwaway unit, the task unit hiding the credential and stopped at its deadline), `scripts/check-no-fault-hooks.sh` (no fault-injection code in the release binary) |
| Agent CI, systemd unit | same run | `systemd-analyze security`: `fleet-agent.service` 1.9 OK, `fleet-agent-recovery.service` 1.6 OK |
| Agent CI, Update smoke test (refusals, rollbacks, recovery) and Dependency audit | same run | Phase 1 update path; `cargo audit --deny warnings` |
| Deploy CI, Image check | [43971294115](https://github.com/hostilecity/fleet-cmdb/actions/runs/43971294115) | The production image starts against four empty databases and builds them (`db:prepare` in `bin/docker-entrypoint`) |
| Agent VM tests (Debian 13 under QEMU, real installer, stub server) | [43961956688](https://github.com/hostilecity/fleet-cmdb/actions/runs/43961956688) | All 13 scenarios passed: 290 (install refusals), 300 (AC-2.3), 301 to 306 (Phase 1 updates), 370 "Package updates applied, no reboot", 371 "Package manager lock held: lock_timeout", 372 "Agent restarted during the upgrade (L8)", 373 "Forced timeout ends the process tree", 307 (recovery mode) |

**The database builds from empty.** CI loads `db/schema.rb` into empty databases (Server CI and Deploy CI above). Running every migration from an empty database was also checked by hand on `78047da` while preparing this runbook: the structure `pg_dump --schema-only` prints is the same as after loading the schema (PostgreSQL 16). Migrating a Phase 2 database forward is not checked: you rebuild from scratch, and NFR-5 waives it until Phase 3 is accepted.

**Earlier suites and fixtures.** The Phase 1 and Phase 2 specs and agent tests are part of the suites above, and every example in `docs/api/examples/` is run by `spec/contract/api_contract_spec.rb` and `agent/tests/contract.rs`. Earlier agent releases and frozen fixtures from earlier phases are not run (NFR-5, P3-ACCEPT's scope).

## 2. The criteria

### AC-3.1: an unknown type or out-of-schema parameter is refused, with no execution

**CI:** server: `spec/requests/task_creations_spec.rb` "gives a forged POST the same validation as the form, refuses it, and audits it (AC-3.1)"; `spec/requests/task_adversarial_spec.rb` "refuses every hostile row when it would be claimed..." (21 rows inserted with SQL) and the validator fuzz; `spec/requests/api/tasks_spec.rb` "records an agent-side refusal of a claimed task with its reason, which is how AC-3.1 is observed". Agent: `a_canary_proves_refused_tasks_run_nothing_and_an_accepted_one_runs`, `every_local_refusal_is_reported_with_its_reason_and_nothing_starts`, `parameters_are_checked_strictly_and_refused_with_nothing_run`, `a_hostile_servers_extra_fields_never_reach_the_task_and_bad_type_ids_are_not_tasks`. The agent half for an unknown type needs a hostile server, which only CI has: a real server never delivers one.

**By hand, three ways in, none through the form.**

**(a) A forged dashboard POST.** Signed in, on any dashboard page, open the browser's developer console and run (with the host's number from its page's URL):

```js
const p3 = (body) => fetch('/tasks', { method: 'POST', body,
  headers: { 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content,
             'Content-Type': 'application/x-www-form-urlencoded' } })
  .then(async (r) => console.log(r.status, new DOMParser().parseFromString(await r.text(), 'text/html').querySelector('#refused')?.innerText));
p3('type=run_shell&parameters[command]=touch+/tmp/p3-canary&target[host_ids][]=HOST_ID');
p3('type=restart_service&parameters[service]=p3-demo.service;touch+/tmp/p3-canary&target[host_ids][]=HOST_ID');
p3('type=refresh_reports&command=touch+/tmp/p3-canary&target[host_ids][]=HOST_ID&second_factor_code=CODE');
```

**Pass:** each answer is `403` or `422`, and its text names the problem: "not a task type in the catalog", the service failing the pattern, "The field command is not accepted" (with the code, the missing confirmation as well). **Tasks** shows no new task. **Audit log**, filtered to "Task creation refused", has three entries with you as the actor and the problems, never the values sent. **Save:** the console output, the audit log page.

**(b) Rows written straight into the database** (past the dashboard, its step-up, and its audit, as a database writer would). On the server VM, save this as `p3-insert.rb`:

```ruby
# P3-ACCEPT helper: inserts one task row for the acceptance VM straight into the database.
# Arguments: TYPE PARAMETERS_JSON TIMEOUT_SECONDS EXPIRES_IN_SECONDS. Prints id, uuid, type, state.
hostname = ENV.fetch("P3_HOST", "vm-p3.example.lan")
type, parameters, timeout, expires_in = ARGV
abort "usage: TYPE PARAMETERS_JSON TIMEOUT_SECONDS EXPIRES_IN_SECONDS" unless expires_in
host = Host.find_by!(hostname:)
batch = Task.where(host_id: host.id).order(:id).last&.task_batch or abort "run any task on #{hostname} from the dashboard first"
Task.connection.exec_insert(<<~SQL, "P3-ACCEPT", [ batch.id, host.id, type, parameters, Integer(timeout), Integer(expires_in) ])
  INSERT INTO tasks (task_batch_id, host_id, task_type, parameters, timeout_seconds, expires_at, created_at, updated_at)
  VALUES ($1, $2, $3, $4::jsonb, $5, now() + make_interval(secs => $6), now(), now())
SQL
task = Task.where(host_id: host.id).order(:id).last
puts [ task.id, task.uuid, task.task_type, task.state ].join(" ")
```

Run one **Refresh reports** on the VM from the dashboard first (the helper puts its rows in that task's batch). Then:

```sh
p3() { docker exec -i -e P3_HOST=vm-p3.example.lan fleet-cmdb bin/rails runner - "$@" < p3-insert.rb; }
p3 run_shell '{"command":"touch /tmp/p3-canary"}' 600 3600
p3 restart_service '{"service":"p3-demo.service; touch /tmp/p3-canary"}' 600 3600
p3 apply_package_updates '{"packages":"openssh-server=1:7.0"}' 600 3600
```

**Pass:** within about a minute (the next heartbeat), each task is **Refused**, `unknown_type` or `invalid_params`, "refused by the server when the agent claimed it · nothing ran", with the system as actor in its audit entries. On the VM, `journalctl -u fleet-agent --since -10min | grep 'task received'` names none of their UUIDs, and `test ! -e /tmp/p3-canary` succeeds. **Save:** the three task pages, the journal excerpt, the canary check.

**(c) A refusal by the agent itself** on the real VM: AC-3.9 below is one (`not_allowed_locally`). For `not_enabled_locally`, do the same steps with `restart_service` removed from `enabled` instead of the service from `allowed_services`. **Pass:** **Refused**, "refused by the agent", nothing ran.

### AC-3.2: no API path takes a shell string or command name; the review note

**CI and review:** [phase-3-security-review.md](../decisions/phase-3-security-review.md) is the review note (every route, every process the agent starts, the searches, the CI checks); the delivery note adds what was re-checked for acceptance. CI: `spec/services/task_batches_spec.rb` "refused requests create nothing (AC-3.2)"; `spec/lib/task_catalog_spec.rb` (the lint); `spec/requests/api/tasks_spec.rb` "delivers only its id, type, parameters, deadline, and catalog version"; "No shell in the task module" in Agent CI.

**By hand**, in a clone at the commit you accept:

```sh
(cd cmdb && bin/rails routes -g 'tasks|second-factor' | grep -v ' GET ')
sh agent/scripts/check-task-spawns.sh && sh agent/scripts/check-task-spawns.sh --self-test
grep -rnE '"/bin/(ba)?sh"|"sh"|"bash"|"-c"|popen|libc::exec|libc::system' agent/src --include=*.rs | grep -v tests.rs
grep -rnE '\bsystem\(|%x|Open3|IO\.popen|Process\.spawn|Kernel\.exec|\beval\(|instance_eval|class_eval' cmdb/app cmdb/lib cmdb/config
```

**Pass:** the routes that change anything are the 13 on `78047da`: the four agent endpoints under `/api/v1/tasks` (poll, start, progress, result), `POST /tasks`, the two cancels, the three task settings, and the three second-factor ones (setup, verify, recovery codes, which take only a code). The task ones are the review's section 3. None takes a command, script, path, or program name; the spawn check prints its "no shell" line and the self-test exits 0; the agent grep finds only lines inside `#[cfg(test)]` modules (in `facts/host.rs`, `facts/users.rs`, `main.rs`, and `tasks/wire.rs` on `78047da`); the server grep finds nothing. On a confirmation page, the folded "exact payload" shows only id, type, parameters, timeout, and catalog version. **Save:** the output, a screenshot of the payload.

### AC-3.3: killing and restarting the agent mid-poll and mid-task never runs a task twice

**CI:** `no_kill_point_in_a_hundred_and_twenty_randomised_runs_runs_a_task_twice` (120 seeded runs with kills at every step, lost poll replies, and replayed ids); `killed_after_received_reports_not_run_and_never_runs_it`, `killed_after_started_reports_interrupted_and_never_runs_it`, `killed_mid_run_reports_interrupted_and_never_runs_it_again`, `killed_after_finished_sends_the_stored_result_unchanged`, `duplicate_delivery_of_one_id_runs_it_once`; server `spec/requests/api/tasks_spec.rb` "delivers an unstarted claimed task again, as after an agent restart, with a fresh lease and no second claim (AC-3.3)" and "never delivers a started task again..."; `spec/services/agent_tasks_concurrency_spec.rb`; VM scenario 372.

**By hand: mid-task.** On the VM, note the time, then arm the kill:

```sh
T=$(date '+%F %T'); grep -m1 -q 'task program starting' <(journalctl -fu fleet-agent -n0); sleep 5; systemctl kill --signal=SIGKILL fleet-agent
```

In the dashboard, create **Restart a service**, `p3-demo.service`, on the VM. The kill lands 5 seconds into `systemctl restart`, while `p3-demo` is still starting. The agent comes back by itself 10 seconds later.

**Pass:** the task ends **Failed**, `interrupted`. `journalctl -u p3-demo --since "$T" -o cat | grep -c '^Started p3-demo.service'` prints `1`: systemd finished the one restart it was asked for, and the agent never asked again. `p3_ledger <uuid>` lists `received`, `started`, `executing`, `finished`, `reported` once each. The agent's journal after the restart reports the task and never logs `task program starting` for it again. **Save:** the task page, the count, the ledger lines, `journalctl -u fleet-agent --since "$T"`.

**By hand: mid-poll** (5 minutes later). Stop the agent (`systemctl stop fleet-agent`), create **Restart a service**, `p3-demo.service`, and wait for it to show **Queued**. Then:

```sh
T=$(date '+%F %T'); systemctl start fleet-agent; grep -m1 -q 'task received' <(journalctl -fu fleet-agent -n0); systemctl kill --signal=SIGKILL fleet-agent
```

**Pass:** the task ends **Failed** with `not_run` or `interrupted` (where the kill landed decides which), or, if the kill came after it ran, **Failed** `interrupted` with one restart. Either way the `grep -c '^Started p3-demo.service'` count above is `0` or `1`, never more, and the ledger has each step at most once. **Save:** the same as above.

**Optional, a package update killed mid-upgrade** (the task unit runs on, threat model L8; scenario 372 restarts the agent where this kills it): build `fvt-slow` as in AC-3.4 with `bash /root/vm-test-packages.sh build fvt-slow 1.0 && bash /root/vm-test-packages.sh build fvt-slow 1.1 'sleep 45'`, install 1.0, publish 1.1, create **Apply package updates**, and kill the agent once `systemctl is-active fleet-agent-task-<uuid>-2.service` says `active`. **Pass:** **Succeeded**, with "the upgrade finished while the agent was restarting" in the output, and `grep -c 'upgrade fvt-slow' /var/log/dpkg.log` is `1`.

### AC-3.4: package updates update the packages, report success with output, and the next package report shows the new versions

**CI:** VM scenario 370 (a real `apt-get upgrade` on Debian 13: one package upgraded, a held one and one needing a removal kept back, `reboot_required` reported and no reboot, needrestart's service named and not restarted, a package report sent); `apply_updates/tests.rs`; `apt.rs` "every program is fixed and follows the policy". The stub server there is not the real one, so the dashboard half needs you.

**By hand**, on the VM as root:

```sh
p=/root/vm-test-packages.sh
bash $p build fvt-demo 1.0 && bash $p build fvt-demo 1.1 'touch /run/reboot-required'
bash $p build fvt-held 1.0 && bash $p build fvt-held 1.1
dpkg -i /srv/fvt/debs/fvt-demo_1.0_all.deb /srv/fvt/debs/fvt-held_1.0_all.deb && apt-mark hold fvt-held
bash $p publish fvt-demo_1.1_all.deb fvt-held_1.1_all.deb
echo 'deb [trusted=yes] file:/srv/fvt/repo ./' > /etc/apt/sources.list.d/fvt.list
cat /proc/sys/kernel/random/boot_id; dpkg-query -W fvt-demo fvt-held; apt-get -q update >/dev/null; apt list --upgradable
```

Then **Refresh reports** on the VM, so the host's **Packages** tab shows `fvt-demo` 1.0, and then **Apply package updates** on it.

**Pass:** the task **Succeeded**, "Reboot required", with `packages_upgraded` and `packages_held_back` (`fvt-held`) in what it reported. The output has `$ /usr/bin/apt-get -q --error-on=any -o DPkg::Lock::Timeout=300 update`, `Unpacking fvt-demo (1.1) over (1.0)`, and the summary at the end. On the VM, `dpkg-query -W fvt-demo fvt-held` shows 1.1 and 1.0, and the boot id is unchanged (no reboot). Within a few minutes the host's **Packages** tab shows `fvt-demo` 1.1, and **Compare** between the last two snapshots shows 1.0 to 1.1 (with any real Debian packages the upgrade also took). **Save:** the task page, the output download, the Packages tab and Compare, the VM's before and after output.

Leave the test repository in place for AC-3.5; the VM is thrown away afterwards.

### AC-3.5: a task over its timeout is terminated on the VM and marked timed out on the server

**CI:** agent `a_task_past_its_deadline_is_killed_with_its_children_and_reported_timed_out`, `a_task_that_ignores_sigterm_is_killed_after_the_grace_period`, `a_transient_unit_past_its_deadline_is_stopped_and_reported_timed_out`, `the_timeout_is_the_lower_of_the_servers_and_the_catalogs`; privilege smoke "package_manager unit is stopped at its deadline"; VM scenario 373 (a maintainer script hanging past a 60-second deadline, its whole tree gone). Server: `spec/services/task_leases_spec.rb` "times out a running task with no result after its deadline and grace when its agent is still heard from (AC-3.5)".

**By hand.** A package whose maintainer script hangs:

```sh
bash /root/vm-test-packages.sh build fvt-hang 1.0 && bash /root/vm-test-packages.sh build fvt-hang 1.1 'sleep 7200'
dpkg -i /srv/fvt/debs/fvt-hang_1.0_all.deb && bash /root/vm-test-packages.sh publish fvt-hang_1.1_all.deb
```

Then either:

- **A, the real limit (about 61 minutes, hands off):** create **Apply package updates** on the VM and come back after an hour.
- **B, faster (about 3 minutes):** a row with a 120-second limit, through the helper from AC-3.1 (b): `p3 apply_package_updates '{}' 120 3600`. Only the time limit differs from A; the agent uses the lower of the server's and its catalog's.

**Pass:** the task is **Timed out**, "Stopped by the agent", and its output says it ran past its deadline and that the package database may need `dpkg --configure -a`. On the VM: `pgrep -af 'sleep 7200'` prints nothing; `systemctl list-units --all 'fleet-agent-task-*'` lists nothing; `dpkg-query -W -f '${db:Status-Abbrev}\n' fvt-hang` is not `ii` (the upgrade was cut). **Save:** the task page, the three commands' output.

**Then the repair** ([troubleshooting.md](troubleshooting.md#the-package-database-needs-repair)), which this leaves you in. Here the hanging script is the cause, so take it out first: `sed -i 's/^sleep 7200$/true/' /var/lib/dpkg/info/fvt-hang.postinst`, then follow the steps. **Pass:** `dpkg --audit` prints nothing and **Apply package updates** succeeds again. **Save:** the commands' output (this is the evidence for the repair documentation).

### AC-3.6: a cancelled queued task never runs

**CI:** `spec/services/task_cancellation_spec.rb` "cancels a queued task at once, with the operator as actor, and it is never delivered (AC-3.6)"; `spec/requests/api/tasks_spec.rb` "never delivers a cancelled queued task (AC-3.6)"; "cancels a claimed task the agent has not started, and refuses its start"; `spec/requests/task_adversarial_spec.rb` (cancel needs the step-up).

**By hand.** Stop the agent (`systemctl stop fleet-agent`). Create **Restart a service**, `p3-demo.service` (task A). On its page, **Cancel task**, enter a code. Create **Refresh reports** (task B). Start the agent: `T=$(date '+%F %T'); systemctl start fleet-agent`.

**Pass:** A is **Cancelled**, "Cancelled before it was delivered", with you as the actor in the audit log. B **Succeeded** within a couple of minutes, which shows the agent polled. `journalctl -u fleet-agent --since "$T" | grep 'task received'` names B's UUID and not A's; `journalctl -u p3-demo --since "$T" -o cat | grep -c '^Started p3-demo.service'` is `0`. **Save:** both task pages, the journal lines.

### AC-3.7: automated tests cover catalog validation, atomic claiming, idempotent execution, timeout, cancellation, and result reporting

**CI only.** The tests, by subject, are in the delivery note's AC-3.7 table. **Pass:** Server CI and Agent CI are green on the commit you accept. **Save:** the two run links.

### AC-3.8: a task left queued past its expiry is never delivered to a returning agent

**CI:** `spec/requests/api/tasks_spec.rb` "never delivers a queued task past its expiry, by the database clock (AC-3.8)", "skips an expired task for the next one that is still valid (AC-3.8)"; `spec/services/task_leases_spec.rb` "expires a queued task at its expiry, and only then (AC-3.8)"; `spec/services/task_leases_concurrency_spec.rb`.

**By hand.** Stop the agent. Then either:

- **A, through the dashboard (a bit over an hour):** in **Settings > Tasks**, set the expiry of "Refresh reports" to 1 hour (code needed). Create **Refresh reports** on the VM. Wait until its page says **Expired** (within a minute after its expiry time). Set the expiry back to 24 hours.
- **B, faster (about 3 minutes):** `p3 refresh_reports '{}' 600 120` (expires in 2 minutes), and wait until its page says **Expired**.

Then start the agent: `T=$(date '+%F %T'); systemctl start fleet-agent`, and wait 5 minutes.

**Pass:** the task stays **Expired**, "never delivered"; its audit entry `task.expired` has the system as actor; `journalctl -u fleet-agent --since "$T" | grep 'task received'` does not name its UUID. **Save:** the task page, the audit entry, the journal lines.

### AC-3.9: the agent refuses a restart that is on the server allowlist but not on its own

**CI:** `agent/src/tasks/restart_service.rs` `refused_names_run_nothing` (its "on the server's allowlist, maybe, but not on this VM's (AC-3.9)" cases; the fake `systemctl`'s call log is the canary); `every_local_refusal_is_reported_with_its_reason_and_nothing_starts`; `spec/requests/api/tasks_spec.rb` "records an agent-side refusal...".

The server leaves out a host whose agent reports that it does not allow the service, so the task has to be created while the server still holds the old report:

1. `p3-demo.service` is in **Settings > Tasks** and in the VM's `allowed_services` (step 0). Stop the agent: `systemctl stop fleet-agent`.
2. In `/etc/fleet-agent/config.toml`, change `allowed_services` to `[]` (keep `restart_service` in `enabled`). `fleet-agent check-config` passes.
3. Create **Restart a service**, `p3-demo.service`, on the VM (it is still targeted, with an offline or stale warning).
4. `T=$(date '+%F %T'); systemctl start fleet-agent`.

**Pass:** the task is **Refused**, `not_allowed_locally`, "refused by the agent · nothing ran". The agent's journal has `task not run: nothing was started` with `reason="not_allowed_locally"` for its UUID; `journalctl -u p3-demo --since "$T" -o cat | grep -c '^Started p3-demo.service'` is `0`. The host's **Tasks** tab now shows no allowed services, and a new restart task leaves the host out (`not_allowed_locally`). **Save:** the task page, the journal lines, the count, the targets page leaving the host out. Then put `p3-demo.service` back in `allowed_services` if you have steps left.

### Each task type works under the installed unit (P3-A05)

Covered by the passes above: **Refresh reports** (step b of AC-3.1, AC-3.6), **Restart a service** (run one more with nothing else going on: **Succeeded**, "Restarted and active"), **Apply package updates** (AC-3.4). Also save `systemd-analyze security fleet-agent.service | tail -n 1` from the VM (CI: 1.9 OK on systemd 255).

## 3. No remote shell, arbitrary command path, automatic reboot, or out-of-scope feature

In a clone at the commit you accept. **Save:** the output of each command.

1. **No remote shell or command path:** AC-3.2 above, and the review note's sections 3 to 5.
2. **The agent never reboots:**

   ```sh
   grep -rnE '"(reboot|poweroff|halt|kexec)"|systemctl (reboot|poweroff)|libc::reboot|reboot\.target' agent/src --include=*.rs | grep -v tests.rs
   ```

   **Pass:** three lines: `agent/src/facts/users.rs` (`"halt"` among the login shells it reads from `/etc/passwd` for the config report), and two in `#[cfg(test)]` code (`reboot.target` as a name `restart_service` refuses, a `"reboot": true` field a heartbeat test sends and the agent ignores). VM scenario 370 and AC-3.4 check the boot id.
3. **No distribution upgrade, no removals, no service restarts by the package task:**

   ```sh
   grep -nE 'dist-upgrade|full-upgrade|--no-remove|Upgrade-Allow-New|cfg\(test\)' agent/src/tasks/apply_updates/apt.rs
   grep -n 'NEEDRESTART_MODE' agent/src/tasks/executor/spawn.rs agent/src/tasks/executor/unit.rs
   ```

   **Pass:** besides the module comment, `--no-remove` and `Upgrade-Allow-New=false` in the upgrade vector, `Upgrade-Allow-New=true` only in the `--simulate` vector that lists held back packages and changes nothing, and `dist-upgrade` and `full-upgrade` only below `#[cfg(test)]`, in the test that checks they are absent; `NEEDRESTART_MODE=l` in both. Scenario 370 checks that the service needrestart names keeps its invocation id.
4. **Nothing out of scope** (requirements, section 1):

   ```sh
   git grep -niE 'esp32|firmware|\bota\b|tenant|kubernetes|hypervisor|remediat' -- cmdb/app cmdb/lib cmdb/config agent/src
   ```

   **Pass:** only test strings (`firmware` as a report type the agent ignores) and the CIS rules' remediation guidance text, which Phase 2 shows and never applies.
5. **Only catalog types exist:** `docs/api/tasks/task-catalog.json` has three types, and `IMPLEMENTED` in `agent/src/tasks/mod.rs` lists the same three. CI: `spec/lib/task_catalog_spec.rb` "is frozen, so nothing can add an entry at runtime"; `the_production_registry_implements_only_the_built_types`.

## 4. After the run

Fill the placeholders in the delivery note with the evidence, post it on #39, and tick the boxes there. The VM can then be deleted; remove its host (**Retire**) and `p3-demo.service` from **Settings > Tasks**.
