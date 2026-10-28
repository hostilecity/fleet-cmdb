# ADR 0014: Task trust model and safeguards

- Status: Accepted (owner, first requirements review); task signing stays rejected, and agent releases are signed separately under [ADR 0018](0018-signed-agent-updates.md)
- Decision issue: DEC-14
- Requirements: `docs/requirements.md`

## Context

The catalog limits what can run, but anyone controlling the server or an operator session can still run any catalog task with schema-valid parameters.

## Decision

- **Agent-side opt-in:** risky task types (`apply_package_updates`, `restart_service`) are **disabled by default** on each agent and enabled per VM in its local config. Only `refresh_reports` is on by default.
- **Agent-side service allowlist** in addition to the server's.
- **Task expiry** (default 24 hours) and **claim leases**.
- **Passkey or TOTP** to create or cancel tasks and change allowlists (ADR 0006).
- **Batch limits:** type the host count to confirm above 3 hosts; hard cap of 25 hosts per batch.
- Cancelling a running, non-interruptible task lets it finish and stops anything further in the same batch from starting.
- Task signing was considered and rejected for now.

## Consequences

- Enabling updates on a VM is a deliberate local edit.
- Because the agent API is private (ADR 0005), a compromise needs access to the LAN as well.
