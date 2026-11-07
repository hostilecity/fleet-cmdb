# CIS-aligned rules: the starter set, adding, and tuning

The server checks each host's configuration against rules that are data, not code ([DEC-12](../decisions/0012-rule-condition-format.md)). The rule format is in [docs/api/rules](../api/rules/README.md). This guide covers the starter set that ships with the server, how to add or tune a rule, and the licensing rules every change must follow ([DEC-10](../decisions/0010-cis-rules.md)).

Passing the rules makes a host **CIS-aligned**. The product never says "CIS compliant": say "passes N of M checks".

## The starter set

`cmdb/config/rules/debian-13.yml` holds 67 rules for Debian 13 (DEC-01). They cover the fact areas in the fact manifest:

- **SSH server**: root login, empty and password logins, host-based trust, `.rhosts`, user environment, PAM, attempt and session limits, login grace time, log level, banner, keep-alives, weak ciphers, key exchange methods, and MACs, forwarding, and access to `sshd_config`.
- **Login and password policy**: password age limits and warning, hashing method, locking inactive accounts, default umask, and `pwquality` length, character classes, and repeats.
- **Local users**: only root has user id 0.
- **Firewall and automatic updates**: a host firewall is enabled, and security updates install automatically.
- **File permissions**: `passwd`, `group`, `shadow`, and `gshadow` and their backups, `sudoers`, `grub.cfg`, `crontab` and the cron directories, and the login banners.
- **Services**: cron, auditd, AppArmor, and the journal run; mDNS, printing, SNMP, DHCP, NFS, rpcbind, Samba, FTP, web servers, telnet, and rsh do not.

Import it on a running server:

```sh
bin/rails rules:import FILE=config/rules/debian-13.yml
bin/rails rules:list
```

Every rule in the file omits `enabled`, so new rules start enabled and a re-import never re-enables a rule you disabled. Importing re-evaluates every host's latest config snapshot; no agent is contacted (P2-S06).

Some rules depend on what a host is for. A web server runs Apache or nginx, and a file server runs NFS or Samba. On such hosts, disable the rule rather than editing it to pass. (Disabling one rule for some hosts only is not supported yet; disabling is fleet-wide.)

Two areas have no rule yet, because a rule inspects one fact and these need two:

- **Time synchronisation**: chrony or systemd-timesyncd, whichever the host uses.
- **The firewall in use**: ufw, nftables, or firewalld.

`firewall.enabled` covers the second in part.

## Adding a rule

1. **Pick the fact** from the manifest (`GET /api/v1/manifest/config`, or `cmdb/config/fact_manifest.yml`). If the fact you need is not there, add it first: see [config-facts.md](config-facts.md).
2. **Give it a key** that is lower case with hyphens, such as `ssh-max-auth-tries`. Never reuse a key for another rule, because results and history are kept by key.
3. **Write the condition** with the operators in [docs/api/rules](../api/rules/README.md#a-rule). Quote `yes`, `no`, `on`, and `off`, because YAML reads them as booleans. For a file or unit that may not exist, wrap the condition in `any: [{ absent: true }, ...]` if a missing file is fine.
4. **Write the title and remediation in your own words** (see "Licensing" below). The title is a short statement of the good state ("SSH does not accept logins as root"), not an instruction. The remediation says what to change and how to apply it.
5. **Set `reference`** to the benchmark section as a pointer only: `CIS Debian Linux 13 v1.0.0 5.1.21`. If no single section matches, name the section the rule belongs to, such as `CIS Debian Linux 13 v1.0.0 2.1`.
6. **Add fixtures**: give the rule a passing and a failing value in `cmdb/spec/fixtures/cis_rules/debian-13.yml`, plus edge cases under `also_pass` and `also_fail`. Choose the values by hand, as a host would report them, so a wrong condition fails its own test.
7. **Run the specs**: `bundle exec rspec spec/rules`. The spec checks four things:
   - the file validates and imports;
   - every rule has fixtures that are valid values for its fact;
   - every rule passes and fails as its fixtures say;
   - the wording rules below are followed.

## Tuning a rule

Edit the rule in the file and import it again. A changed condition, title, severity, or remediation becomes a new version of the rule: old versions stay readable, results name the version that produced them, and the change is audited with before and after values. Then every host is re-evaluated. Change the fixtures with the rule.

To keep your own thresholds without editing the shipped file, keep a copy of the file and import that instead. Keys that the copy no longer lists stay as they are unless you import with `DISABLE_MISSING=1`.

## Licensing (DEC-10)

CIS Benchmarks are licensed CC BY-NC-SA 4.0, and CIS's terms for non-members restrict derivative works, reposting, and claiming a compliance level. The repository is public. So, for every rule:

- **Write everything in your own words.** Nothing is copied from a CIS document: not titles ("Ensure ..."), audit steps, rationale, impact, or remediation text. Describe the setting and how to fix it as you would to a colleague.
- **Section numbers are pointers only.** A reference names the benchmark and section, nothing more.
- **Facts, not text.** Configuration values (`PermitRootLogin no`, a file mode, a list of weak algorithm names) are technical facts about the software, not CIS text.
- **Say "CIS-aligned"**, never "CIS compliant", in the rules, the dashboard, and the docs. A spec checks the repository for the claim.
- **Review it in the PR**: each pull request that adds or changes rules records the review against DEC-10. If there is any doubt about a rule, keep it out of the repository and import it at runtime instead.

This is not legal advice; DEC-10 records the decision and its open question.
