# Security policy

Fleet CMDB manages credentials for, and (in Phase 3) can run maintenance tasks on, the machines it monitors. Please report security problems privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a suspected vulnerability.

Include what you found, how to reproduce it, and the version or commit. You can expect an acknowledgement within a few days. This is a personal homelab project, so there is no formal SLA or bounty.

## Scope

In scope: the Rails server and dashboard (`cmdb/`), the agent (`agent/`), the agent API, and the deployment configuration in this repository.

Particularly interesting reports, given the design (`docs/requirements.md`):

- Any way to make the server send, or the agent run, something that is not an allowlisted task type with schema-valid parameters
- Any way to read or write another host's data with a different host's credential
- Any way to reach the agent API through the public dashboard hostname
- Secrets (credentials, tokens, keys) appearing in logs, errors, audit entries, or task output
- Markup injection into the dashboard through agent-reported data

## Handling secrets in this repository

No real hostnames, addresses, certificates, keys, tokens, or fleet details belong in the repository, including issues and pull requests. Use example values such as `vm-01.example.lan`. If you find a committed secret, report it privately as above so it can be rotated.
