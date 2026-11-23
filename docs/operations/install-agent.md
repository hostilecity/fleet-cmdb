# Install, update, and remove agents

How to put the agent on a VM, enroll it, keep it updated, roll back, and remove it. The server must be installed with at least one release imported first ([install-server.md](install-server.md)). **Install agents from the first release that includes Cloudflare's Origin CA roots ([agent/trust](../../agent/trust/README.md), ADR 0024)**: older agents do not trust the server's certificate. The agent's own reference (every option, exit code, file, and the update mechanism) is [agent/README.md](../../agent/README.md); this page is the operator's path through it.

**VM requirements:** Debian 13 on x86_64 with systemd ([DEC-01](../decisions/0001-fleet-profile.md)), root, `curl` and `minisign` (both Debian packages), HTTPS access to the agent hostname (`fleet-vm.example.com`) on port 443, and HTTPS access to GitHub (`raw.githubusercontent.com`) for the release public key. The VM must resolve the agent hostname through the LAN DNS, and its clock must be right (`timedatectl` shows `System clock synchronized: yes`).

## Install one VM (approved in the dashboard)

The primary path is the dashboard's **Agents > Install an agent** page. It shows the exact commands for the newest imported release, with its version filled in. The page comes from the server, and what you copy from it can differ from what it shows (hidden text, or a script that changes what is copied). So open this guide on GitHub yourself (`docs/operations/install-agent.md` in `github.com/hostilecity/fleet-cmdb`), not from a link on the page. Paste one step at a time and, before you press Enter, check what you pasted in the terminal against this guide: only the server's address and the version may differ. (Debian 13's bash waits for Enter after a paste.) The steps are:

1. **Install the tools** on the VM, as a user who can use sudo:

   ```sh
   sudo apt-get update && sudo apt-get install -y curl minisign && sudo -k
   ```

   `sudo -k` makes sudo forget your password, so a `sudo` hidden in a later pasted command cannot reuse it. Steps 2 and 3 never need root and never ask for a password: if one does, stop, because something in it is not from this guide. It is not a full defence: a hidden command could, for example, define its own `sudo` that catches your password at step 4. Checking what you pasted against this guide is what protects you.

2. **Download** the agent into a new private directory: the binary, its signed manifest, and the manifest's signature, from the agent hostname:

   ```sh
   cd "$(mktemp -d)"
   curl -fsSL -o fleet-server-ca.pem https://raw.githubusercontent.com/hostilecity/fleet-cmdb/refs/tags/agent-v1.2.0/agent/trust/cloudflare-origin-ecc.pem
   curl -fL --cacert fleet-server-ca.pem -o fleet-agent https://fleet-vm.example.com/api/v1/releases/1.2.0/binary
   curl -fL --cacert fleet-server-ca.pem -o fleet-agent.manifest.json https://fleet-vm.example.com/api/v1/releases/1.2.0/manifest
   curl -fL --cacert fleet-server-ca.pem -o fleet-agent.manifest.json.minisig https://fleet-vm.example.com/api/v1/releases/1.2.0/signature
   ```

   `mktemp -d` makes a directory only you can write to, so no other user on the VM can swap a file between the check and the install, and nothing from an earlier attempt is reused. Stay in it, in the same shell, until step 4.

   curl knows only the VM's system trust store, and the server's certificate comes from Cloudflare's Origin CA (ADR 0024), so the second line fetches that authority's certificate from the repository on GitHub (`agent/trust`, at the release's tag) and the downloads hand curl that one authority. The page names `cloudflare-origin-ecc.pem` or `cloudflare-origin-rsa.pem`, whichever signed the server's certificate. The VM's trust store is not changed. The agent itself trusts the authority from its build. With a publicly trusted server certificate the page leaves out that line and `--cacert`.

3. **Check the signature.** Get the release public key from the repository on GitHub, at the release's own tag, not from the server:

   ```sh
   curl -fsSL -o fleet-release-key.pub https://raw.githubusercontent.com/hostilecity/fleet-cmdb/refs/tags/agent-v1.2.0/agent/release-keys/current.pub
   ```

   Then check the manifest's signature with that key, and the binary against the SHA-256 in the manifest minisign has just verified. The pattern is the whole manifest of release 1.2.0 with only its SHA-256 left open (on the page, the version is the one you are installing, with its dots written `\.`):

   ```sh
   minisign -V -p fleet-release-key.pub -m fleet-agent.manifest.json -o | sed -n 's/^{"format":"fleet-agent-release-manifest\/1","version":"1\.2\.0","target":"x86_64-unknown-linux-musl","sha256":"\([0-9a-f]\{64\}\)","size":[0-9]*}$/\1  fleet-agent/p' | sha256sum -c
   ```

   It must print exactly these three lines, with the version you are installing:

   ```text
   Signature and comment signature verified
   Trusted comment: fleet-agent 1.2.0 x86_64-unknown-linux-musl release manifest
   fleet-agent: OK
   ```

   Anything else means the files are not that release as it was signed, and nothing has run. Do not run the agent: delete the files and start again. If it fails again, treat the server as suspect. Typical failures:

   | Output | Meaning |
   |---|---|
   | `fleet-agent: FAILED` | The binary is not the one the signed manifest names (changed, or the download was cut short) |
   | `Signature verification failed` | The manifest or its signature was changed |
   | `Signature key id in fleet-agent.manifest.json.minisig is … but the key id in the public key is …` | The release was signed by a key that is not the repository's. With minisign 0.11 (Debian 12), an ID that starts with `0` is printed without its leading zeros; it is the same key the page names with 16 digits |
   | `Trusted comment: fleet-agent <another version> …`, then `no properly formatted checksum lines found` | A signed release, but not the one the command names (for example an older one) |
   | `curl: (22) … 404` on the key | No such release tag on GitHub, or the VM cannot reach GitHub (below) |

   **Why this way.** The server could be wrong or compromised, and so could anyone who can present a certificate for the agent hostname (ADR 0024). A checksum the server shows next to a binary it serves proves nothing about either. The release key is never on the server (ADR 0018), so a binary that passes this check is the release the command names, as the release workflow signed it. The key comes from the release's own tag, so it is the key that signed that release, before and after a [key rotation](../releases.md#rotation). But the server renders the whole page, so it could change any command, not only the key's address: that is why the commands must match this guide. To check the key by hand as well, compare `fleet-release-key.pub` with the keys printed in [docs/releases.md](../releases.md#where-they-are). They are, today:

   | Key | ID | Public key |
   |---|---|---|
   | current | `7E51EF010B459985` | `RWSFmUULAe9RfnlQTNeEW6nsdcGfhgNJPuipo3oDnhdS+7UrsuOUg1WL` |
   | next | `E23D49AE6F91A17B` | `RWR7oZFvrkk94qBZYEVnm1cgefAWGIpPGSGyzROt/C6FqaiaBCXIMEEU` |

   **A VM without access to GitHub:** write the key by hand instead of downloading it, from the table above (the key whose ID the page names), and run the same check. Copy the certificate authority from `agent/trust` in the repository the same way.

   ```sh
   printf '%s\n' 'untrusted comment: minisign public key 7E51EF010B459985' 'RWSFmUULAe9RfnlQTNeEW6nsdcGfhgNJPuipo3oDnhdS+7UrsuOUg1WL' > fleet-release-key.pub
   ```

   The page warns in red when the server's configured release keys differ from the repository's. A release it accepted only with such a key fails this check. Fix the keys ([docs/releases.md](../releases.md#generating-the-keys-once-by-the-owner)); if nobody changed them, treat the server as compromised.

4. **Run the installer** as root, in the same directory:

   ```sh
   chmod +x fleet-agent && sudo ./fleet-agent install --server https://fleet-vm.example.com
   ```

   This is the first command that needs your password. It checks the VM (Debian 13, systemd, a server certificate it trusts) and changes nothing if a check fails. Then it installs the binary under `/usr/lib/fleet-agent`, writes the systemd unit, and prints an approval link and a code such as `WDJB-MJHT`, then waits (10 minutes by default).

5. **Approve** in the dashboard: open the link, or **Approve a VM** on the Fleet page. Check that the code matches the terminal, review what the VM reported, fill in the host's name, tags, and notes, and choose **Approve**. If the VM's machine ID or hostname matches an existing host, choose whether this is a re-enrollment of that host or a new one. A VM cloned from a template usually has the template's machine ID: choose **A new host**, and see [VMs cloned from one template](troubleshooting.md#vms-cloned-from-one-template).

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
2. On the VM, install the tools, download, and check the agent as above (steps 1 to 3), then run the installer with the token on standard input, never on the command line:

   ```sh
   chmod +x fleet-agent && sudo ./fleet-agent install --server https://fleet-vm.example.com --token-stdin
   ```

   On a terminal it asks for the token with the input hidden; a provisioning tool pipes it in instead. The token is never accepted as a command-line value, so it cannot end up in the process list or shell history.

   The **Unattended** tab of the install page has a ready cloud-init snippet. It installs `curl` and `minisign` with cloud-init's `packages`, then runs the same download and check as one `sh -ec` script, so a failed check stops it before the agent runs. It works in `/root`, which only root can write to. Check the template file itself against this guide before you use it: from then on the template, not the server, decides which release (the version is written into the check) and which key a new VM gets. A token works once: a template that clones many VMs needs one pre-registration per VM.

**Check:** as for one VM; the host moves from **Pending** to **Online**.

## Update agents

### Remotely, in a rollout

Agents update themselves only to a newer release signed by the release key, verified on the VM, with automatic rollback if the new version does not confirm within 5 minutes ([ADR 0018](../decisions/0018-signed-agent-updates.md)). A rollout offers a release in stages: canary hosts first, then a percentage of the rest, then all; any failure or rollback halts it.

1. Import the new release on the **Agents** page.
2. Under **Start a rollout** on the same page, choose the release, the canary hosts (a tag, or hosts you pick), and the later stages (by default `25, 100`, or `1, 10, 50, 100` from 1,000 active hosts; set `FLEET_ROLLOUT_LARGE_FLEET_HOSTS` to change that threshold, [configuration.md](configuration.md)). You can type other stages in the form. Choose **Start rollout…** and confirm. Every action is in the audit log with your account as the actor.

   The next stage opens by itself when all hosts of the current one have confirmed. **Advance to the next stage** opens it now.
3. **Check:** the Agents page shows each stage's progress live. Each host's agent version on the Fleet page changes to the new release, and its page lists the update as succeeded. On a VM: `fleet-agent --version` and `journalctl -u fleet-agent | grep -i update`.

**The systemd units come with the update** (#232). Once the new version has confirmed, the agent checks that version's units with `systemd-analyze verify`, writes them (`fleet-agent.service` and the rollback and recovery units), and reloads systemd, without restarting the service. They take effect at the next start of the service, usually a reboot. Unit files you replaced by hand (without the installer's first line, `` # Written by `fleet-agent install` ``) are left alone: keep local changes in a drop-in (`systemctl edit fleet-agent`). If the units cannot be written, the update still succeeds and the host's update history says why. The new units come from the agent being replaced, so a host updated from a release older than this one gets them only at its next update; run the installer by hand to set them up at once.

**Find hosts without recovery mode.** On the **Fleet** page, set **Recovery mode** to **Not set up**: it lists the hosts whose agent would stop for good after a crash loop on a confirmed version ([ADR 0030](../decisions/0030-agent-recovery-mode.md)), including agents too old to say and hosts where the agent could not check. Each host's page says what to do under **Agent updates**. On a VM: `sudo fleet-agent install --refresh-units` writes the installed version's units, reloads systemd, and changes nothing else; it waits for no update and none starts while it runs. For a host whose agent does not report it, update the agent first: its own release has no recovery mode.

**When a rollout halts** (a host reported `failed` or `rolled_back`, or did not report within 30 minutes): no further host is offered the update. The Agents page shows why, and which hosts did not succeed ([troubleshooting.md](troubleshooting.md#a-rollout-halted)). Then choose **Resume** or **Cancel rollout**. A halted rollout never resumes by itself.

### By hand, on one VM

Download and check a newer release as in [Install one VM](#install-one-vm-approved-in-the-dashboard) and run the installer again:

```sh
sudo ./fleet-agent install
```

On an enrolled VM it keeps the credential and every setting, installs the new binary as `current`, keeps the old one as `previous`, writes its systemd units, and restarts the service. Nothing needs approving. This is also the way to repair an installation, and to update a VM that missed a release key change ([docs/releases.md](../releases.md#rotation)).

**Check:** `fleet-agent --version` and the host's agent version in the dashboard show the new release.

## Roll back

- **Automatic.** A remote update that does not confirm (no heartbeat accepted by the server within `update_confirm_seconds`, default 300), whose service fails to start, or that is interrupted by a reboot, is rolled back to the previous version by the agent itself, which reports `rolled_back` with the reason. Nothing to do but read the reason ([troubleshooting.md](troubleshooting.md#an-update-was-rolled-back)).
- **By hand.** The server never offers an older version (no downgrades, ADR 0018). To go back on one VM, run the installer of the older release you trust: download and check it as in [Install one VM](#install-one-vm-approved-in-the-dashboard), from the install page's `?version=` link or from its GitHub release ([docs/releases.md](../releases.md#verifying-a-download-by-hand)), then `sudo ./fleet-agent install`. To withdraw a bad release from the whole fleet, publish a newer, fixed release and roll it out.

## Uninstall

```sh
sudo fleet-agent uninstall
```

It stops and disables the service and removes the unit, the binaries under `/usr/lib/fleet-agent`, `/usr/bin/fleet-agent`, the config with its credential, and the state in `/var/lib/fleet-agent`, then lists what it removed. `--keep-state` keeps the config and state, for a reinstall that keeps the credential. Files it did not create are listed and left alone.

**Check:** `systemctl status fleet-agent` reports the unit not found, and `ls /etc/fleet-agent /usr/lib/fleet-agent` finds nothing.

Uninstalling does not change the server: the host goes **Offline** after 15 minutes and stays on the dashboard. If the VM is gone for good, **Retire** it ([fleet-operations.md](fleet-operations.md#retire-a-host)); its history stays in the audit log.
