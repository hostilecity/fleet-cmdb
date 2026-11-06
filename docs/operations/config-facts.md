# Configuration facts: the manifest and how to add a fact

The server publishes a versioned list of the configuration facts an agent may report (FR-2.1): `cmdb/config/fact_manifest.yml`, served at `GET /api/v1/manifest/config`. Config reports ([P2-S02](../backlog/specs/p2-config-reports.md)) carry a value for each fact, and CIS-aligned rules ([P2-S05](../backlog/specs/p2-cis-engine.md)) inspect those values. The manifest names fact keys only, never commands; an agent decides how to read a fact it knows and reports the rest as unsupported, so adding a fact never needs the agent to run anything the server names.

## What a fact is

| Field | Meaning |
|---|---|
| `key` | A dotted lower-case name such as `sshd.permitrootlogin`. File and service facts are generated from the `files` and `services` lists as `file:<path>` and `service:<unit>`. |
| `type` | `string`, `integer`, `boolean`, `string_list`, `file_attributes` (`{mode, owner, group}`, or `null` when the file does not exist), or `service_state` (`{active, enabled}`, or `null` when the unit is not installed). |
| `since` | The manifest version that introduced it. |
| `description` | What it is, for the operator. |
| limits | `max_length` (string); `minimum` and `maximum` (integer); `max_items` and `item_max_length` (string_list). Published, so an agent bounds what it collects. Each has a default (see `ConfigManifest::CONSTRAINTS`). |
| `example` | A valid value, used by the specs. Not published. |

A report's value for a fact is checked against these rules by `ConfigManifest::Fact#value_errors`, so the manifest alone decides what is acceptable.

## Adding a fact

1. **Edit `cmdb/config/fact_manifest.yml`.** Raise `manifest_version` by one, if this change is the first since the last release of the manifest, and give the new fact that `since`. For a file or a service, add an entry under `files` or `services` instead of a fact.
2. **Add its line to `cmdb/spec/fixtures/config_manifest/frozen_facts.yml`**, with the same type, `since`, and limits. Never edit an existing line there.
3. **Write the agent's reader** ([P2-AGENT-FACTS](../backlog/specs/p2-agent-facts.md)). Until it exists, agents report the fact as `unsupported`, which the server accepts and shows.
4. **Add a rule** that uses the fact, if one is wanted ([P2-CIS-RULES](../backlog/specs/p2-cis-rules.md)).
5. Run `bin/ci` in `cmdb/`. The manifest spec loads the manifest, checks every example against its own fact's rules, checks it against the published schema, and compares it with the frozen list.

## What is never done

A released fact is never removed, renamed, or given another type, and its limits are loosened or kept, never tightened. A report made against an older manifest version must stay valid, and a rule written against a fact must keep meaning the same thing. To change what a fact means, add a new key and leave the old one in place; the `frozen_facts.yml` specs fail otherwise. Changing the manifest type set itself (`ConfigManifest::CONSTRAINTS`) is a breaking contract change and needs a new schema version (`docs/api/README.md`, "Changing a schema").

## Safety

- The manifest lists no commands, paths to run, or arguments. Files are read with `stat` only (mode, owner, group), never their contents; for `/etc/shadow` and the like that is the whole point of listing them.
- No fact may carry secret material. The user facts hold names, ids, homes, and shells, never hashes.
- Every list has a `max_items`, so a hostile or broken agent cannot send an unbounded report.
