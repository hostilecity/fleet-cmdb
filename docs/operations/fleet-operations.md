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

**Recovering a lost credential** is the same thing: the server stores only a hash, so a lost credential cannot be shown again; re-enroll instead. If the VM was cloned from another enrolled VM, the host page warns of a machine ID mismatch; re-enroll the clone as a **new host**, and the original keeps its own credential.

## Retire a host

Use it when the VM is gone for good. Uninstall the agent first if the VM still exists ([install-agent.md](install-agent.md#uninstall)), then on the host's page, **Retire**, typing the hostname to confirm. Its credential is revoked, it leaves the fleet list and counts, and its history stays in the audit log. Hosts are never deleted.

## Change the liveness thresholds

A host is **Online** if it sent a heartbeat within 3 minutes, **Stale** within 15, otherwise **Offline**. Change these on **Settings**, or:

```sh
docker exec fleet-cmdb bin/rails settings:show
docker exec fleet-cmdb bin/rails settings:liveness ONLINE_MINUTES=3 STALE_MINUTES=15
```

The next evaluation, within a minute, applies them. Data retention (90 days) is changed the same way: [health-and-jobs.md](health-and-jobs.md#retention).

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

## Task settings

**Settings > Tasks** holds the server's side of what tasks may do (P3-S06). Every change asks for a code from your authenticator app and is recorded in the audit log with the values before and after.

- **Services that can be restarted:** empty at first, so the "Restart a service" task refuses everything (ADR 0015). Add a full unit name such as `nginx.service`, for every host or for the hosts with one tag. Each VM must also list it in `[tasks] allowed_services` in `/etc/fleet-agent/config.toml`. The agent's own units, SSH, `systemd-*`, networking, and D-Bus are refused, here and on every VM; restart them from the console.
- **Limits:** the most hosts in one batch (up to 25), the output kept per task (4 KiB to 1 MiB), the poll interval agents are asked to use, and how long each task type may wait before it expires (1 hour to 7 days, 24 hours by default). Changes apply to what happens next; tasks already queued keep their expiry.

Removing a service, revoking a host's credential, re-enrolling it, or retiring it never runs anything: queued restarts of a removed service are refused when their agent picks them up, and a host's queued tasks are cancelled when it is revoked, re-enrolled, or retired.

## Read the audit log

**Audit log** in the top bar lists every entry, newest first: who (an operator, a host, or the system), what, on which host or object, and when (UTC), with the before and after values of edits. Filter by actor, action, host, and date range, or hide sign-ins; the filters are in the URL, so a filtered view can be bookmarked. A host's page shows its own entries, with **All entries for this host**.

Entries are never edited or deleted, by the dashboard or in the database (a trigger refuses it), and are kept regardless of the retention setting.
