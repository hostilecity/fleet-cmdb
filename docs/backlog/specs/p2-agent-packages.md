# P2-AGENT-PACKAGES: Agent package collector (dpkg)

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- Detect the package manager rather than assuming one. Only `dpkg` is supported ([DEC-01](../../decisions/0001-fleet-profile.md)); a VM without it reports `unsupported` with a reason.
- Collect every installed package: name, full version including epoch and release, architecture, and source package name (dpkg's `Source` field, falling back to the package name). Use a machine-readable query format with fixed arguments.
- Send within the package report ([P2-S08](p2-packages.md)) with gzip request compression; bound the memory used for large package lists.
- Same cadence and request handling as the config report ([P2-A01](p2-agent-facts.md)).
- Fixtures from real manager output for each fleet distribution, including packages with epochs, plus-signs, tildes, and multiple architectures.

## Acceptance criteria

- [ ] The reported set equals the output of the VM's own package listing, with no packages missing or invented (AC-2.3 check)
- [ ] Source package names are present where the manager records them
- [ ] An unsupported manager is reported explicitly
- [ ] Peak memory on a 3,000-package host stays modest (measured and noted)
