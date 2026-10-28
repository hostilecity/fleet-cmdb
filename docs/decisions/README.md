# Architecture decision records

One file per decision, numbered in the order decided. Copy `0000-template.md` to add one. An accepted ADR is not edited to reverse it; add a new ADR that supersedes it.

| ADR | Decision | Issue |
|---|---|---|
| [0001](0001-fleet-profile.md) | Fleet profile: Debian 13, x86_64 | DEC-01 |
| [0002](0002-server-stack.md) | Server stack baseline | DEC-02 |
| [0003](0003-agent-privilege.md) | Agent runs as root under a hardened unit | DEC-03 |
| [0004](0004-enrollment.md) | Single-use enrollment token (amended by 0017: now pre-registration) | DEC-04 |
| [0005](0005-hosting-tls-deployment.md) | Docker Compose; Cloudflare tunnel for the dashboard; private agent API | DEC-05 |
| [0006](0006-operator-authentication.md) | Google OAuth allowlist; app-level second factor for tasks | DEC-06 |
| [0007](0007-snapshots-and-retention.md) | Snapshot semantics and retention | DEC-07 |
| [0008](0008-api-conventions.md) | Agent API conventions | DEC-08 |
| [0009](0009-repository.md) | Public repository, MIT license, hygiene | DEC-09 |
| [0010](0010-cis-rules.md) | CIS rules: own wording, "CIS-aligned" | DEC-10 |
| [0011](0011-vulnerability-data.md) | OSV data for Debian 13 | DEC-11 |
| [0012](0012-rule-condition-format.md) | Declarative rule condition format | DEC-12 |
| [0013](0013-on-demand-reports.md) | Report-request directive in the heartbeat response | DEC-13 |
| [0014](0014-task-trust-model.md) | Task trust model and safeguards | DEC-14 |
| [0015](0015-restartable-services.md) | Restartable services allowlist | DEC-15 |
| [0016](0016-package-update-policy.md) | Package update task policy | DEC-16 |
| [0017](0017-agent-onboarding.md) | Onboarding from the installer, approved in the dashboard | DEC-17 |
| [0018](0018-signed-agent-updates.md) | Signed remote agent updates with automatic rollback | DEC-18 |
| [0019](0019-scale-direction.md) | Design direction toward enterprise scale | DEC-19 |
