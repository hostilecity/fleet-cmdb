# Troubleshooting

Start with the two logs: the agent's on the VM (`journalctl -u fleet-agent -n 50`) and the server's (`sudo docker compose logs --since 1h app` in `/opt/fleet-cmdb`). Every API error the agent logs carries a `request_id`; search the server log for it to see the server's side of the same request ([health-and-jobs.md](health-and-jobs.md#logs)).

## The agent hostname certificate is not trusted

The installer stops with `presented a certificate this VM does not trust`, or the agent logs TLS errors and the host goes offline.

1. **Is the VM's clock right?** `timedatectl`: a clock far off makes every certificate look invalid. Fix time synchronisation first.
2. **Which certificate does the server present?**

   ```sh
   echo | openssl s_client -connect agent.fleet.example.com:443 -servername agent.fleet.example.com 2>/dev/null \
     | openssl x509 -noout -subject -issuer -enddate
   ```

   - Issuer `Let's Encrypt` and a future `notAfter`: the certificate is fine; check the VM's trust store (`apt install --reinstall ca-certificates`).
   - Issuer `TRAEFIK DEFAULT CERT`: Traefik has no certificate for the name. Read `sudo docker compose logs traefik | grep -i acme` on the server. Usual causes: `ACME_EMAIL` left at a placeholder (`invalidContact … forbidden domain`), a DNS token without Zone:Read and DNS:Edit on the right zone, `FLEET_AGENT_HOST` not in that zone, or Let's Encrypt's rate limit after many attempts (use `ACME_CA_SERVER` with the staging URL while testing, then delete `/var/lib/fleet-cmdb/certs/acme.json` and restart Traefik).
   - Issuer `(STAGING)`: `ACME_CA_SERVER` still points at staging. Comment it out, delete `certs/acme.json`, `sudo docker compose up -d traefik`.
   - A `notAfter` in the past: renewal has been failing; the Traefik log says why (often a revoked or expired Cloudflare token).
3. **Is the name pointing at the server?** `getent hosts agent.fleet.example.com` on the VM must give the server's LAN address. A different address means the LAN DNS record is missing or the VM uses another resolver.

Only for a private certificate authority (not the default setup): pass `--ca-file ca.pem` to the installer.

## The dashboard does not open through a tunnel on another machine

In the layout where `cloudflared` runs on another machine ([install-server.md](install-server.md#existing-postgresql-and-a-tunnel-on-another-machine-deployed-by-github-actions)), Cloudflare shows an error page or the connector logs errors for `fleet.example.com`.

- **`502` and a certificate error in the connector's log:** the dashboard certificate is not issued yet (`docker compose logs traefik | grep -i acme` on the server), or the public hostname lacks **Origin Server Name** `fleet.example.com`. Never turn on **No TLS Verify** instead.
- **`403` from the server:** Traefik does not see the connector's address in `FLEET_TUNNEL_SOURCE_RANGE`. Check the address the connector's machine uses on the LAN (`ip -br addr` there) and the variable, then deploy again. If the server's Docker publishes ports through its userland proxy for that traffic, Traefik sees a Docker gateway address instead and refuses everything: that fails closed, and needs Docker's default iptables port publishing.
- **`404` from the server:** the request did not carry the dashboard hostname (leave **HTTP Host Header** empty in the public hostname), or `FLEET_TUNNEL_SOURCE_RANGE` is not set, so nothing is routed on port 8443.
- **Connection refused or timed out:** port 8443 is blocked between the two machines, or `FLEET_DASHBOARD_BIND_ADDRESS` is an address the connector does not reach.

## The agent gets `401`

The agent logs `the server rejected this agent's credential (it may have been revoked, or the host retired)`. The credential is unknown to the server: the host was revoked or retired, it was re-enrolled from another machine, or the config was copied from another VM. The host page shows which. Re-enroll the VM ([fleet-operations.md](fleet-operations.md#re-enroll-a-host-new-credential)); for a retired host, enroll it as a new host instead. The agent retries about every 30 minutes and recovers on its own once re-enrolled with `fleet-agent install --reenroll`.

`403 reenrollment_required` means a re-enrollment was started for the host; finish it on the VM with the command the dashboard showed.

## The clock is off

The agent logs `this host's clock differs from the server's`. The server always uses its own clock for liveness and audit times, so a wrong VM clock does not make a host look offline, but report timestamps are off and, if it is far off, TLS fails (above). Enable time synchronisation on the VM (`timedatectl set-ntp true`; check `timedatectl` shows `System clock synchronized: yes`). The agent logs `this host's clock agrees with the server's again` once fixed. Check the server's clock the same way.

## A host stays offline

1. On the VM: `systemctl status fleet-agent`. If it is not running, `journalctl -u fleet-agent -n 50` says why (often a config error, exit code 78, which names the key at fault).
2. If it is running, its log shows whether requests fail: `cannot reach the fleet server` is a network, DNS, or certificate problem (above); `401` is a credential problem (above); `429` means rate limiting, which resolves itself.
3. On the server: `curl -s https://agent.fleet.example.com/health`. If `job_liveness` is `failing`, the liveness evaluation is not running, so no host's status changes: check `sudo docker compose ps` and `sudo docker compose logs app`, and the failed jobs page.

## The onboarding request expired

The installer stops with `the onboarding request expired before an operator approved it; nothing was enrolled` (exit code 5). Nothing was created on the server. Run the same install command again for a new code, and approve it within 10 minutes (`FLEET_ONBOARDING_TTL_MINUTES`). If the approval page says the code is unknown, it was mistyped, already decided, or expired: start again. If the installer refuses to start with too many waiting requests, approve or reject the pending ones on the approval page first.

## A rollout halted

A rollout halts when any host reports `failed` or `rolled_back`, or when a host sent the update has not reported within 30 minutes (`unconfirmed`). It then offers the update to no further host until an operator resumes or cancels it ([install-agent.md](install-agent.md#remotely-in-a-rollout)).

1. Read why: `Rollout.order(:id).last.halt_reason` in the console, and the `update.*` and `rollout.*` entries in the audit log.
2. For each host that did not succeed, read its log on the VM: `journalctl -u fleet-agent | grep -i update`. `failed` means the update was refused before anything changed (a download, signature, checksum, free-space, or self-test failure: the reason says which); the VM still runs the old version.
3. `unconfirmed` usually means the host was offline or could not reach the release download; once it is back, it reports, and the result is recorded.
4. Fix the cause, then resume. If the release itself is bad, cancel the rollout and publish a fixed, newer release; never try to push an older one.

## An update was rolled back

The host's update history and the audit log show `rolled_back` with a reason, and the VM runs the previous version again. The agent rolls back when the new version does not get a heartbeat accepted within 5 minutes, when its service fails to start or keeps failing, or when the VM restarts during the update. On the VM:

```sh
journalctl -u fleet-agent -u fleet-agent-update -u fleet-agent-rollback --since "1 hour ago"
fleet-agent --version                     # the version it rolled back to
cat /var/lib/fleet-agent/update-result.json   # only until the server has accepted the result
```

The new version's own log lines, before the rollback, say why it did not confirm: often it could not reach the server, or a config option it does not accept. Fix that and run a new rollout, or upgrade that VM by hand ([install-agent.md](install-agent.md#by-hand-on-one-vm)).

## `/health` is unhealthy

`curl -s https://agent.fleet.example.com/health` names the failing check; [health-and-jobs.md](health-and-jobs.md) explains each. On a new installation, `backup` fails until the first backup runs, and `job_liveness` until a minute or two after a start; both are expected.
