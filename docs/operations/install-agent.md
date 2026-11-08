# Install, update, and remove agents

How to put the agent on a VM, enroll it, keep it updated, roll back, and remove it. The server must be installed with at least one release imported first ([install-server.md](install-server.md)). **Agents can be installed only once the agent hostname is served with TLS ([#137](https://github.com/hostilecity/fleet-cmdb/issues/137)); until then this page describes what comes next.** The agent's own reference (every option, exit code, file, and the update mechanism) is [agent/README.md](../../agent/README.md); this page is the operator's path through it.

**VM requirements:** Debian 13 on x86_64 with systemd ([DEC-01](../decisions/0001-fleet-profile.md)), root, `curl`, and HTTPS access to the agent hostname (`agent.fleet.example.com`) on port 443. The VM must resolve the agent hostname through the LAN DNS, and its clock must be right (`timedatectl` shows `System clock synchronized: yes`).

## Install one VM (approved in the dashboard)

The primary path is the dashboard's **Agents > Install an agent** page. It shows the exact commands for the newest imported release, with its download URL and SHA-256 filled in. Copy them from there; the shape is:

1. **Download** the agent on the VM, from the agent hostname:

   ```sh
   curl -fL -o fleet-agent https://agent.fleet.example.com/api/v1/releases/1.2.0/binary
   ```

2. **Check** it against the SHA-256 on the page (the page fills it in):

   ```sh
   echo "<sha256 from the page>  fleet-agent" | sha256sum -c
   ```

   It must print `fleet-agent: OK`. If it does not, do not run it: download it again.
3. **Run the installer** as root:

   ```sh
   chmod +x fleet-agent && sudo ./fleet-agent install --server https://agent.fleet.example.com
   ```

   It checks the VM (Debian 13, systemd, a server certificate it trusts) and changes nothing if a check fails. Then it installs the binary under `/usr/lib/fleet-agent`, writes the systemd unit, and prints an approval link and a code such as `WDJB-MJHT`, then waits (10 minutes by default).

4. **Approve** in the dashboard: open the link, or **Approve a VM** on the Fleet page. Check that the code matches the terminal, review what the VM reported, fill in the host's name, tags, and notes, and choose **Approve**. If the VM's machine ID or hostname matches an existing host, choose whether this is a re-enrollment of that host or a new one.

The installer then saves the credential to `/etc/fleet-agent/config.toml` (mode 0600), starts `fleet-agent.service`, waits for the service's first accepted heartbeat, and ends with `Done. fleet-agent is installed, enrolled, and running.`

**Check:**

```sh
systemctl is-active fleet-agent            # active
journalctl -u fleet-agent -n 20            # heartbeat and inventory lines, no errors
fleet-agent --version                      # the release you installed
```

In the dashboard the host shows **Online** within a minute, with its inventory (OS, disks, interfaces) on its page. The audit log has the approval and the enrollment.

If anything fails, the installer says what happened and what to do next, and exits with a code that says which kind of failure it was ([agent/README.md](../../agent/README.md#install-onboarding-and-uninstall)). Common cases are in [troubleshooting.md](troubleshooting.md).

## Install unattended (pre-registration)

For cloud-init, templates, and scripts, where nobody is at the terminal to approve:

1. In the dashboard, **Pre-register host** on the Fleet page: enter the name and hostname. The page shows a **one-time token**, once, valid for 24 hours (`FLEET_ENROLLMENT_TOKEN_TTL_HOURS`). The host appears as **Pending**.
2. On the VM, download and check the agent as above, then run the installer with the token on standard input, never on the command line:

   ```sh
   chmod +x fleet-agent && sudo ./fleet-agent install --server https://agent.fleet.example.com --token-stdin
   ```

   On a terminal it asks for the token with the input hidden; a provisioning tool pipes it in instead. The token is never accepted as a command-line value, so it cannot end up in the process list or shell history.

   The **Unattended** tab of the install page has a ready cloud-init snippet. A token works once: a template that clones many VMs needs one pre-registration per VM.

**Check:** as for one VM; the host moves from **Pending** to **Online**.

## Update agents

### Remotely, in a rollout

Agents update themselves only to a newer release signed by the release key, verified on the VM, with automatic rollback if the new version does not confirm within 5 minutes ([ADR 0018](../decisions/0018-signed-agent-updates.md)). A rollout offers a release in stages: canary hosts first, then a percentage of the rest, then all; any failure or rollback halts it.

1. Import the new release on the **Agents** page.
2. Start the rollout. Its dashboard view arrives with [P1-UPDATES](../backlog/specs/p1-updates.md) (issue #59); until then it is started from the server console, and each action is audited with your account as the actor:

   ```sh
   docker exec -it fleet-cmdb bin/rails console
   ```

   ```ruby
   me = Operator.find_by!(email: "you@example.com")
   release = AgentRelease.find_by!(version: "1.3.0")
   rollout = Rollouts.start!(release:, actor: me, canary_tag: "canary")   # or canary_host_ids: [12, 15]
   rollout.rollout_hosts.group(:stage, :state).count                      # progress
   ```

   The next stage opens by itself when all hosts of the current one have confirmed; `Rollouts.advance!(rollout, actor: me)` opens it now. Default stages: the canaries, then 25%, then 100% of the hosts running an older version.
3. **Check:** each host's agent version on the Fleet page changes to the new release, and its page lists the update as succeeded. On a VM: `fleet-agent --version` and `journalctl -u fleet-agent | grep -i update`.

**When a rollout halts** (a host reported `failed` or `rolled_back`, or did not report within 30 minutes): no further host is offered the update. Find out why, `Rollout.order(:id).last.halt_reason`, and the host's audit entries and `journalctl -u fleet-agent` on that VM ([troubleshooting.md](troubleshooting.md#a-rollout-halted)). Then either `Rollouts.resume!(rollout, actor: me)` or `Rollouts.cancel!(rollout, actor: me)`. A halted rollout never resumes by itself.

### By hand, on one VM

Download and check a newer release as in [Install one VM](#install-one-vm-approved-in-the-dashboard) and run the installer again:

```sh
sudo ./fleet-agent install
```

On an enrolled VM it keeps the credential and every setting, installs the new binary as `current`, keeps the old one as `previous`, and restarts the service. Nothing needs approving. This is also the way to repair an installation, and to update a VM that missed a release key change ([docs/releases.md](../releases.md#rotation)).

**Check:** `fleet-agent --version` and the host's agent version in the dashboard show the new release.

## Roll back

- **Automatic.** A remote update that does not confirm (no heartbeat accepted by the server within `update_confirm_seconds`, default 300), whose service fails to start, or that is interrupted by a reboot, is rolled back to the previous version by the agent itself, which reports `rolled_back` with the reason. Nothing to do but read the reason ([troubleshooting.md](troubleshooting.md#an-update-was-rolled-back)).
- **By hand.** The server never offers an older version (no downgrades, ADR 0018). To go back on one VM, run the installer of the older release you trust: download and check it from GitHub or the install page's `?version=` link, then `sudo ./fleet-agent install`. To withdraw a bad release from the whole fleet, publish a newer, fixed release and roll it out.

## Uninstall

```sh
sudo fleet-agent uninstall
```

It stops and disables the service and removes the unit, the binaries under `/usr/lib/fleet-agent`, `/usr/bin/fleet-agent`, the config with its credential, and the state in `/var/lib/fleet-agent`, then lists what it removed. `--keep-state` keeps the config and state, for a reinstall that keeps the credential. Files it did not create are listed and left alone.

**Check:** `systemctl status fleet-agent` reports the unit not found, and `ls /etc/fleet-agent /usr/lib/fleet-agent` finds nothing.

Uninstalling does not change the server: the host goes **Offline** after 15 minutes and stays on the dashboard. If the VM is gone for good, **Retire** it ([fleet-operations.md](fleet-operations.md#retire-a-host)); its history stays in the audit log.
