# ADR 0015: Remotely restartable services

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-15
- Requirements: `docs/requirements.md`

## Context

The restart task takes a service name and must refuse unsafe ones.

## Decision

The server and agent allowlists are **empty** until services are named. The agent's own units (`fleet-agent` and any `fleet-agent-*`), `sshd`/`ssh`, and `systemd-*` are always refused, even if listed. Networking and `dbus` are also protected. A protected name covers its template instances too (`sshd@blue.service`).

## Consequences

- The restart task refuses everything until the owner adds services on both the server and the VM.
- Services are added by editing the allowlists, never by a free-text task parameter.
