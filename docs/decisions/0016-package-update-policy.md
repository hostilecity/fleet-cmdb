# ADR 0016: Package update task policy

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-16
- Requirements: `docs/requirements.md`, section 10

## Context

"Apply updates" hides choices that change risk, and killing a package manager can damage the dpkg database.

## Decision

Debian only: `apt-get update` then `upgrade` (never `dist-upgrade`, no removals), non-interactive, keep local configuration (`--force-confold`, `--force-confdef`), respect holds, wait a bounded time for the dpkg lock. **Never reboot**; report `reboot_required` and services needing restart (for example via `needrestart`) without restarting them. There is **no security-only scope**. Timeout 60 minutes; on timeout terminate gently and report that the dpkg database may need repair (`dpkg --configure -a`). Not interruptible once running. The agent triggers a package report afterwards.

## Consequences

- The task has no parameters in Phase 3's first release.
