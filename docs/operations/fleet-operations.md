# Day-to-day fleet operations

Everything here is done in the dashboard, signed in as an operator, and every action is recorded in the audit log with your account as the actor. Server commands run on the server VM, as the deploy user, as `docker exec fleet-cmdb bin/rails …`.

## Revoke a host's credential

Use it when a VM may be compromised or its credential leaked. On the host's page, **Revoke credential**, and confirm.

The agent's next request is refused with `401` at once; the host shows as **Revoked**. The agent keeps running and logs that its credential was rejected, retrying about every 30 minutes. To let it back in, re-enroll it (below).

**Check:** the host's page shows the credential as revoked, and on the VM `journalctl -u fleet-agent` shows `the server rejected this agent's credential`.

## Re-enroll a host (new credential)

Use it after a revocation, when a VM lost `/etc/fleet-agent/config.toml`, or when it was rebuilt under the same name. On the host's page, **Re-enroll**, then either:

- **Approve from the VM (recommended):** on the VM, as root, `fleet-agent install --reenroll`. It prints a code; approve it on the approval page, choosing **Re-enroll** of this host. Nothing changes until you approve.
- **One-time token:** **Issue one-time token**, then on the VM `fleet-agent install --token`. The host moves to **Pending**; its current credential keeps working until the token is used.

The old credential stops working the moment the new one is issued. **Check:** the host returns to **Online**, and its page shows the new credential's key id.

**Recovering a lost credential** is the same thing: the server stores only a hash, so a lost credential cannot be shown again; re-enroll instead. If a VM was cloned from another enrolled VM, agent config included, both use one credential and the host page warns of a machine ID mismatch; on the clone run `fleet-agent install --reenroll` and approve it as a **new host**. Then re-enroll the original as the same host: its credential stays the original's, but only a re-enrollment clears the warning. For VMs cloned from one template before the agent was installed, see [troubleshooting.md](troubleshooting.md#vms-cloned-from-one-template).

## Retire a host

Use it when the VM is gone for good. Uninstall the agent first if the VM still exists ([install-agent.md](install-agent.md#uninstall)), then on the host's page, **Retire**, typing the hostname to confirm. Its credential is revoked, it leaves the fleet list and counts, and its history stays in the audit log. Hosts are never deleted.

## Change the liveness thresholds

A host is **Online** if it sent a heartbeat within 3 minutes, **Stale** within 15, otherwise **Offline**. Change these on **Settings**, or:

```sh
docker exec fleet-cmdb bin/rails settings:show
docker exec fleet-cmdb bin/rails settings:liveness ONLINE_MINUTES=3 STALE_MINUTES=15
```

The next evaluation, within a minute, applies them. Data retention (90 days) is changed the same way: [health-and-jobs.md](health-and-jobs.md#retention). So are the vulnerability badge settings (#262): `bin/rails settings:vulnerability_badges REPORT_DAYS=3 GRACE_DAYS=7` sets how old a package report may be before a host's run badge and progress are withheld, and how long a run is kept through a new fixable critical ([configuration.md](configuration.md)).

## Manage operators

```sh
docker exec fleet-cmdb bin/rails operators:allow EMAIL=someone@example.com
docker exec fleet-cmdb bin/rails operators:list
docker exec fleet-cmdb bin/rails operators:disallow EMAIL=someone@example.com   # signed out on their next request
```

Also add or remove the address in the Cloudflare Access policy ([install-server.md](install-server.md#3-publish-the-dashboard-through-the-tunnel)): both must allow someone for them to sign in.

## Reset an operator's second factor

Each operator sets up their own authenticator app under **Settings > Your second factor**, and needs it to create or cancel tasks and change task settings (P3-S09). A lost phone with saved recovery codes needs nothing from you: a recovery code works anywhere a 6-digit code is asked for, including moving to a new phone. With neither phone nor recovery code, only the console can reset it, on purpose, so someone who took over an operator's Google session cannot reset it from the dashboard:

```sh
docker exec fleet-cmdb bin/rails second_factor:reset EMAIL=someone@example.com
```

It removes their authenticator and recovery codes, ends any step-up window, and records `second_factor.reset` in the audit log with the system as actor. Check that the request really comes from the operator (in person or on a channel other than the dashboard) before running it. They then set up a new one, which asks for a fresh Google sign-in first.

## Remote tasks

A task runs one action from a fixed catalog (`docs/api/tasks/task-catalog.json`) on a host: **Refresh reports**, **Restart a service**, or **Apply package updates**. The dashboard cannot send a command, a script, or a program name, and each VM decides for itself what it will run (ADR 0014). Three things must line up before a task runs: the VM turns the task type on, the server allows it (for restarts, the service is on its allowlist), and you pass the second factor. What each task type may do on the VM, and as whom, is in [agent-task-privileges.md](agent-task-privileges.md).

### Turn task types on for a VM

Only **Refresh reports** is on by default. **Restart a service** and **Apply package updates** stay off on every VM until you list them there. As root on the VM, in `/etc/fleet-agent/config.toml`:

```toml
[tasks]
enabled = ["refresh_reports", "restart_service", "apply_package_updates"]
allowed_services = ["nginx.service"]       # only for restart_service; full unit names, at most 64
```

Then check it and restart the agent:

```sh
fleet-agent check-config      # exit 0, or exit 78 and the mistake
systemctl restart fleet-agent
```

- `enabled` lists the task types this VM runs. Leave the key out for the default (`refresh_reports` alone); `enabled = []` turns every task off.
- `allowed_services` is this VM's own restart allowlist: exact unit names such as `nginx.service`. A template instance (`postgresql@17-main.service`) must be listed by its full name, but the server's list takes no `@` instances (below), so such a restart cannot be created yet. Empty by default, so every restart is refused here even when the server allows it (AC-3.9).
- Never restarted, even when listed: the agent's own units (`fleet-agent*`), `ssh` and `sshd`, `systemd` and `systemd-*`, `networking`, `NetworkManager*`, `ifup@*`, `dbus` and `dbus-broker`, template instances included, and any name that is a symbolic-link alias of one of them. Listing one is a mistake in the section.
- `apply_package_updates` has no settings: its policy is fixed (ADR 0016).
- **A mistake turns every task type off** on that VM (fail safe): an unknown type, a malformed, protected, or repeated service, an unknown key. Heartbeats and reports carry on, the agent logs the error at start, and `check-config` names the mistake (it never repeats a service name). A misspelt section name (`[task]`) is a mistake of the whole file and stops the agent, as any unknown key does.
- How often the agent polls is `[task_poll]` (300 s by default, see [agent/README.md](../../agent/README.md#tasks)); a heartbeat tells it at once when a task is waiting, so you rarely need to change it.

**Check:** within a minute the host's **Tasks** tab, under what the agent will run, lists the types and the services as the VM reported them. A host whose agent does not report a type is left out of every task of that type, with the reason shown when you choose targets.

To turn a type off again, remove it from `enabled` and restart the agent. Tasks of that type already queued for the VM are refused by the agent (`not_enabled_locally`) when they arrive, with nothing run.

### Task settings (the server's side)

**Settings > Tasks** holds the server's side of what tasks may do (P3-S06). Every change asks for a code from your authenticator app and is recorded in the audit log with the values before and after.

- **Services that can be restarted:** empty at first, so the "Restart a service" task cannot be created (ADR 0015). Add a full unit name such as `nginx.service` (lower case, ending in `.service`, no `@` instances, at most 64 entries), for every host or for the hosts with one tag. A restart needs the service on this list (for that host's tags) **and** in the VM's `allowed_services`. The protected units above are refused here too; restart them from the console.
- **Limits:** the most hosts in one batch (1 to 25, default 25), the output kept per task (4 KiB to 1 MiB, default 64 KiB), the poll interval agents are asked to use (10 to 300 s, default 300; a heartbeat tells an agent at once when a task is waiting, so this only bounds how late a task starts if that is missed), and how long each task type may wait before it expires (1 hour to 7 days, 24 hours by default). Changes apply to what happens next; tasks already queued keep their expiry.

Removing a service, revoking a host's credential, re-enrolling it, or retiring it never runs anything: queued restarts of a removed service are refused when their agent picks them up (`not_allowed_on_server`, by the server), and a host's queued tasks are cancelled when it is revoked, re-enrolled, or retired.

### The second factor (step-up)

Creating a task, cancelling one, and changing **Settings > Tasks** each need a 6-digit code from the authenticator app you set up under **Settings > Your second factor** (P3-S09). The server checks it on every one of those requests, however it was sent.

- The code box is on the confirmation page itself: one submit checks the code and does the action.
- After an accepted code, the same browser session needs no new code for 5 minutes (the page says "Checked" and until when). The window is fixed from that code and is not extended by use; another browser or session needs its own code.
- Each code is accepted once. 5 wrong codes in 15 minutes lock the step-up for that operator for 15 minutes, in every browser; the refusal and the lock are in the audit log.
- A recovery code works wherever a code is asked for. With neither phone nor recovery code, see [Reset an operator's second factor](#reset-an-operators-second-factor).
- Without a second factor set up, **New task** and the cancel buttons are replaced by an explanation.

### Run a task

**Tasks > New task**, or **Run a task on this host** on a host's page:

1. **Type.** Each type says in plain words what it runs, its time limit, whether it can be stopped once running, and how many hosts will run it. A type is drawn unavailable, with why, when no host runs it or (restarts) the allowlist is empty.
2. **Parameters.** Only **Restart a service** has one: the service, chosen from the server's allowlist. There is no text box.
3. **Targets.** A tag, or hosts picked by name or hostname. The page lists the hosts that get the task and the hosts left out with the reason (not active, agent does not support or enable the type, service not on this host's list). Offline and stale hosts stay in, with a warning: their task waits until they poll, or until it expires.
4. **Confirm.** The steps the agent will take, and folded, the exact programs and the payload the server sends. Above 3 hosts, type the number of hosts. Enter your code, then **Create N tasks**.

One task is created per host, each independent. The batch page (several hosts) and each task's page update live. A host runs one task at a time; the next waits in the queue.

### Cancel a task

On a task's page, the button says what it can do; it opens a confirmation page, whose button asks for the code:

| The task is | Button | What happens |
|---|---|---|
| **Queued** (not delivered yet) | **Cancel task** | Cancelled at once. The agent never receives it (AC-3.6) |
| **Claimed** (delivered, not started) | **Cancel task** | Cancelled at once. If the agent tries to start it, the server answers "do not run", and it drops it |
| **Running**, and it can be stopped (**Refresh reports**) | **Stop task** | The agent hears it with its next progress report (about every 15 s), stops, and the task ends **Cancelled**. Reports already sent stay |
| **Running**, and it cannot be stopped (**Restart a service**, **Apply package updates**) | **Request cancel**, then **Cancel what has not started** (or **Record a cancel request anyway** when nothing else waits) | The task runs to the end and keeps its real result, with "cancel requested" beside it. Every task of its batch that has not started is cancelled |

On a batch page, **Cancel the rest of this batch** does the same for every task of the batch and says how many it will and will not change. Finished tasks never change. If the task started or went back to the queue while you were on the confirmation page, nothing is done and the page is drawn again with its new state.

### What each result means

The task page shows the state and the reason in words, the reason code beside them, what the agent reported (`reboot_required`, services using old libraries, whether the unit is active, reports sent), the timeline, and the output (escaped text; **Download as a text file** gives it as a file). The reason codes:

| The task ends as | Reason | What it means, and what to do |
|---|---|---|
| **Succeeded** | — | Nothing to do. For package updates the page says if the VM needs a reboot; the task never reboots, so reboot when it suits you |
| **Refused** (nothing ran) | `not_enabled_locally` | The VM has not turned this type on: add it to `[tasks] enabled` (above) |
| | `not_allowed_locally` | The service is not in the VM's `allowed_services` (AC-3.9) |
| | `protected_service` | This unit is never restarted remotely, by design. Use the console |
| | `not_allowed_on_server` | The service left the server's allowlist (or this host's tag left its entry) after the task was created; refused by the server when the agent claimed it |
| | `unknown_type`, `invalid_params` | The type or the parameters fail the catalog. The dashboard never creates these; they mean a task reached the database another way, or a server and an agent with different catalogs. Refused by whichever side checked first: the line under the heading says which (the heading currently words both as the agent's) |
| | `not_supported` | The agent cannot run this type here: it is too old ([update it](install-agent.md#update-agents)), or, for package updates, the VM has no `apt` and `dpkg` |
| **Failed** | `nonzero_exit` | The program failed: a service that did not come back (`systemctl status` is in the output), or apt-get failing. Read the output. After a failed upgrade, see [the package database needs repair](troubleshooting.md#the-package-database-needs-repair) |
| | `lock_timeout` | Another program held apt's or dpkg's lock for more than 5 minutes (often `unattended-upgrades`). Nothing was upgraded. Run it again later |
| | `interrupted` | The agent stopped mid-task (a restart, a VM reboot, an update) and said so when it started again. It never runs the task again. Check the VM, then create a new task if still needed |
| | `not_run` | The agent received the task but the server took it back before it started (the claim lapsed). Nothing ran |
| | `lease_expired` | The agent said it started, then stopped reporting until the deadline passed. Set by the server. Look at the VM: the agent's journal says what happened |
| | `agent_error` | The agent could not run it for a reason of its own (for example its task ledger is damaged and on hold). The agent's journal says why |
| **Timed out** | — | The agent stopped the task at its time limit (or, if no result came, the server marked it). For package updates, see [the package database needs repair](troubleshooting.md#the-package-database-needs-repair) |
| **Expired** | — | The host did not poll before the expiry, usually because it was offline. It is never delivered later. Create the task again when the host is back |
| **Cancelled** | — | See [Cancel a task](#cancel-a-task) |

On the VM, `journalctl -u fleet-agent` logs every task decision with the task's id: `task received`, `task not run: nothing was started` (with the reason), `task recorded as started`, `task program starting`, `task result accepted by the server`.

## Read the audit log

**Audit log** in the top bar lists every entry, newest first: who (an operator, a host, or the system), what, on which host or object, and when (UTC), with the before and after values of edits. Filter by actor, action, host, and date range, or hide sign-ins; the filters are in the URL, so a filtered view can be bookmarked. A host's page shows its own entries, with **All entries for this host**.

Entries are never edited or deleted, by the dashboard or in the database (a trigger refuses it), and are kept regardless of the retention setting.
