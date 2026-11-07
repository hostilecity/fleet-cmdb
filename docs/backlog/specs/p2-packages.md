# P2-PACKAGES: Package reports, snapshots, diffs, and dpkg version comparison

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## P2-S08: Package report endpoint, snapshots, and diff

### Scope

- `POST /api/v1/reports/packages`: report id, schema version, package manager (`dpkg`; `unsupported` with a reason; or `unreadable` with a reason, when dpkg is there but its packages could not be listed; rpm and apk are out of scope per [DEC-01](../../decisions/0001-fleet-profile.md)), and packages with name, full version including epoch, architecture, and source package name. Support gzip-compressed request bodies; set a size limit sized for a few thousand packages.
- Storage: the host's current package set in a normalised table (needed by matching, [P2-S11](p2-vulns.md)) and dated snapshots stored compactly, created only when the set changes (content hash). Duplicate report ids deduplicated as before.
- Diff service for two package snapshots: installed, removed, skipped, and version-changed packages.
- Triggers vulnerability matching ([P2-S11](p2-vulns.md)) after a new snapshot.
- An explicitly unsupported manager is stored as such and shown, not treated as an empty package list. So is an unreadable one, which also keeps the last known package set.
- Owner decisions (skipped packages): a package the agent could not install in full (dpkg states `unpacked`, `half-installed`, `half-configured`, `triggers-awaited`, `triggers-pending`), or an entry it could not carry but whose name it could read, is not in `packages`; its name and a short reason are in the optional `skipped` array (at most 64). The diff shows such a package, when it was installed in the earlier snapshot and is named in the later snapshot's `skipped`, as skipped ("Skipped / incomplete"), never as removed. Skipped is matched by name, so it covers every architecture of the name. `warnings` stays for everything else.
- Delivered as `POST /api/v1/reports/packages` (`docs/api`, `packages.request`; `cmdb/README.md`, "Package reports"). The body may be gzip: up to 4 MiB of JSON, plain or decompressed (read only that far), and 1 MiB compressed; 20,000 packages at most. Versions are any printable ASCII without spaces, so one dpkg only warns about is never refused. Storage: `host_package_sets` (manager, reason, count, content hash, warnings), `host_packages` (one row per package, indexed by source), `package_snapshots` (the set as compact rows, written only when the hash changes, retained like inventory snapshots), `package_report_receipts`. `PackageDiff` lists installs, removals, and changes, each an upgrade or downgrade by dpkg order, and is not available when either side is an unsupported manager (an unknown set, not an empty one) ([P2-S09](#p2-s09-package-version-comparison-library-dpkg)). Showing an unsupported manager is part of [P2-DASH-HOST](p2-dash-host.md); the call to vulnerability matching after a new snapshot was added with [P2-S11](p2-vulns.md), which builds the matching (`VulnerabilityMatchJob.after_snapshot`).
- Delivered for skipped and unreadable (P2-S08 follow-up): `manager` gains `unreadable` (the reason is in `unsupported_reason`, whose name is kept so the first contract does not change; no packages; `skipped` must be empty) and `skipped` is optional, so an agent that sends neither is unchanged. Migration `AddSkippedAndUnreadableToPackages`: `skipped` (jsonb, default `[]`) on `host_package_sets` and `package_snapshots`, and the manager and reason constraints (the reason is present exactly when the manager is not `dpkg`). The content hash includes `skipped` only when there are skipped names, so existing sets keep their hash and get no new snapshot. An unreadable report is stored with its reason and writes a snapshot with no packages (once per change of reason); the host's `host_packages` rows and `package_count` are kept as the last readable report left them, and `PackageDiff` is not available to or from that snapshot (an unknown set), while `PackageDiff.for` compares the snapshot after it with the one before it (`previous_known`). `PackageDiff` gains `skipped` (`PackageDiff::Skip`: name, architecture, the earlier package, the reason); install, removal, and change are as before.
- Vulnerability findings and skipped packages (owner decision): a skipped package is not in `host_packages`, so matching treats it as not installed: its findings resolve as `removed`, and reopen when the package is listed again. Matching is not changed for skipped packages. (Keeping them open until the package is listed or really removed would need the matcher to read the skipped names, or `host_packages` to keep the last known row, which would break "stored set equals reported set"; the owner decided against it.) An unreadable report is different: `HostContext` marks the host not evaluated (`unreadable_packages`) and its findings stay as they were, like an unsupported manager.
- Measured (`spec/requests/api/package_reports_spec.rb`, sandbox, PostgreSQL in the same machine): a 3,000-package report (280 KiB of JSON, 27 KiB gzip) stores in 0.33 s; a report changing 300 of them in 0.31 s; their diff takes 0.04 s.

### Acceptance criteria

- [ ] A report round-trips: stored set equals reported set, no packages added or missing
- [ ] Diff shows installs, removals, and version changes
- [ ] Unsupported managers are recorded explicitly
- [ ] An unreadable package database is recorded explicitly with its reason, and the last known set is kept
- [ ] A skipped package is stored and shown in the diff as skipped, not removed
- [ ] A realistic 3,000-package report stores and diffs within a reasonable time (measured and noted)

## P2-S09: Package version comparison library (dpkg)

### Context

String comparison of versions is explicitly not acceptable (FR-2.4). Each package manager has its own ordering.

### Scope

- A dpkg comparator (epoch, upstream version, revision, tilde handling), the only scheme in the fleet profile ([DEC-01](../../decisions/0001-fleet-profile.md)). Structure it behind a small interface so another scheme could be added by a later decision, but build none now.
- Evaluate existing Ruby gems against the reference tools before writing code; if implementing, port from the reference algorithm.
- A conformance corpus of at least 200 version pairs with expected results **generated by the reference tool** (`dpkg --compare-versions` on Debian 13), committed as fixtures together with the generation script.
- Clear failure mode for unparseable versions (the comparison reports "invalid", matching treats it as not evaluated).
- Delivered as `PackageVersions` (`cmdb/lib/package_versions.rb`, `cmdb/lib/package_versions/dpkg.rb`), a port of dpkg's `parseversion` and `verrevcmp`: what dpkg refuses with an error is invalid, with dpkg's reason; what it only warns about compares as dpkg compares it. An empty string and non-ASCII text are invalid too, deliberately. The corpus is `cmdb/spec/fixtures/dpkg/compare-versions.tsv` (235 pairs), generated by `cmdb/script/dpkg-corpus.sh`; Server CI reruns it with `--check` in `debian:13`. Gems evaluated against the corpus: `deb_version` 1.0.3 disagrees on 12 pairs (it compares versions dpkg refuses and splits a colon in the upstream version wrongly) and has no invalid outcome; `apt-pkg` and `ruby-debian` are native extensions last released in 2020 and 2012. So no gem is used.

### Acceptance criteria

- [ ] Conformance corpus passes for each supported manager
- [ ] Known tricky cases pass (epochs, tildes, leading zeros, `+deb12u1` style revisions, alpha suffixes)
- [ ] Sorting a mixed list never raises
