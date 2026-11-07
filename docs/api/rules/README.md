# CIS-aligned rule files

Rules are data, never code ([DEC-12](../../decisions/0012-rule-condition-format.md)). The operator keeps them in a YAML (or JSON) file and imports it; the server checks the whole file and stores nothing unless every rule is right. Rules are worded in our own words with CIS section numbers as pointers only ([DEC-10](../../decisions/0010-cis-rules.md)), and the product says "CIS-aligned", never "CIS compliant".

- Schema: [`v1/cis-rules.schema.json`](v1/cis-rules.schema.json) (format 1). Examples the tests check: [`v1/examples/`](v1/examples/).
- Starter set: [`cmdb/config/rules/debian-13.yml`](../../cmdb/config/rules/debian-13.yml), 67 rules for Debian 13. Adding and tuning rules, and the licensing rules for them: [docs/operations/cis-rules.md](../../operations/cis-rules.md).
- Import: `bin/rails rules:import FILE=rules.yml` (add `DISABLE_MISSING=1` to disable rules the file no longer lists); `bin/rails rules:list`. See `cmdb/README.md`, "CIS-aligned rules".
- These files are not part of the agent API: agents never see rules, so a rule change needs no agent update (FR-2.2).

## A rule

```yaml
format_version: 1
rules:
  - key: ssh-root-login-off            # stable; never reused for another rule
    reference: "CIS Debian Linux 13 v1.0.0 5.1.21"  # a pointer only, no benchmark text
    title: SSH does not let root log in
    severity: high                     # low, medium, high, or critical
    applies_to:
      - distribution: debian           # os-release ID
        versions: ["13"]               # os-release VERSION_ID; omit for every release
    fact: sshd.permitrootlogin         # a key from the fact manifest (GET /api/v1/manifest/config)
    condition: { eq: "no" }            # quote yes, no, on, and off: YAML reads them as true and false
    remediation: Set PermitRootLogin to no in /etc/ssh/sshd_config and reload ssh.
    enabled: true                      # optional; when omitted, an import leaves the flag as it is
```

A rule inspects one fact. Its condition is one operator, or a combinator of conditions on that fact:

| Operator | Value types | Passes when |
|---|---|---|
| `eq`, `ne` | string, integer, boolean, list | the value equals (or does not equal) the operand. A list operand is compared as the fact compares lists: ignoring order unless the manifest marks the list `ordered` |
| `in`, `not_in` | string, integer, boolean, list | the value is (is not) one of the operand's values. For a list fact: every entry is one of them (no entry is) |
| `gte`, `lte` | integer | the value is at least (at most) the operand |
| `matches` | string, list | the whole value matches the regular expression (anchored at both ends, time-limited). For a list fact: every entry matches |
| `mode_at_most` | file | the file's mode grants nothing the operand does not (`0640` allows `0600`, not `0644`) |
| `present`, `absent` | file, service | the file or unit exists (does not exist). The operand is always `true`. Other facts always have a value when they are readable |
| `all`, `any`, `not` | | every, at least one, or not the given condition(s) |

A file fact (`file:<path>`) is `{mode, owner, group}`, or null when the file does not exist, and a service fact (`service:<unit>`) is `{active, enabled}`, or null when the unit is not installed. A missing file or unit equals nothing, is in nothing, and matches nothing, so it passes only `absent`, `ne`, and `not_in`. An empty list passes `in`, `matches`, and `not_in`. Apart from `present`, `absent`, and `mode_at_most`, a condition on them names the part it tests with `field`:

```yaml
condition:
  all:
    - { mode_at_most: "0640" }
    - { field: owner, eq: root }
    - { field: group, in: [root, shadow] }
```

What the import checks, beyond the schema: every key appears once, the fact is in the manifest, each operator fits the fact's type and its operand fits the value (so `eq: no` on a string fact is refused with a hint), patterns compile on their own, and a condition has at most 64 parts nested at most 8 deep.

## Versions

A rule is never edited in place. An import that changes a rule's definition (anything but its key and enabled flag) stores a new version and audits the before and after values; an unchanged rule gets no new version, whatever the order of its keys in the file. Old versions stay readable, and results record the version that produced them (P2-S06). Enabling and disabling are audited too.
