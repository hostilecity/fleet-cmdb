# ADR 0006: Operator authentication

- Status: Accepted (owner, first requirements review)
- Decision issue: DEC-06
- Requirements: `docs/requirements.md`

## Context

The dashboard needs sign-in. Phase 3 makes a hijacked session equal to remote execution.

## Decision

- Sign-in is **Google OAuth against an email allowlist**, as in `homealert`. There are no application passwords and no sign-up.
- Creating or cancelling tasks and changing task allowlists additionally requires an **app-level passkey (WebAuthn) or TOTP**, enforced on the server.
- Google was checked: its OIDC supports `prompt` values `none`, `consent`, and `select_account` only, with no forced re-login and no `max_age`, and `auth_time` only when requested and enabled. Forcing a fresh Google login therefore cannot be relied on, which is why the second factor lives in the application.

## Consequences

- The first operator is added to the allowlist from the command line; users are keyed by Google account.
- A recovery path for a lost passkey or authenticator is documented (console or rake) without weakening the check.
- NFR-1's password-hashing line no longer applies.
