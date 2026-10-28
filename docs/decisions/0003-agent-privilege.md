# ADR 0003: Agent runtime privilege model

- Status: Accepted (owner, first requirements review); see [ADR 0018](0018-signed-agent-updates.md) for the signed update path, the one way the server can cause new agent code to run
- Decision issue: DEC-03
- Requirements: `docs/requirements.md`

## Context

Phase 2 reads root-only data and Phase 3 performs maintenance, while the principles ask for least privilege.

## Decision

The agent runs as **root under a hardened systemd unit**.

## Consequences

- The config file is mode `0600`, owned by root; the state directory is root-owned under `/var/lib/fleet-agent`.
- Systemd sandboxing is applied as far as tasks allow. Package updates need write access to `/usr`, `/etc`, `/boot`, and `/var`, so hardening is reviewed per task in Phase 3 and a per-task privilege table is kept.
- Agent compromise means root on that VM; mitigations are no inbound ports, no arbitrary command execution, and the allowlists in ADR 0014.
