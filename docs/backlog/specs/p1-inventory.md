# P1-INVENTORY: Inventory report endpoint with snapshots

Implementation details for the GitHub issue with this key. The issue states only the goal and acceptance criteria; this file is the source of truth for everything else. Goal, requirement IDs, acceptance criteria, and blockers live in [`../issues.yml`](../issues.yml).

## Scope

- `POST /api/v1/reports/inventory` with the required fields from FR-1.3, a report id, a schema version, and a per-field collection warnings list. Null fields with warnings are accepted; unknown enum values are rejected.
- Storage per [DEC-07](../../decisions/0007-snapshots-and-retention.md):
  - A table of recently seen report ids per host (unique), so retried reports are recognised and answered `200` with `{"duplicate": true}`.
  - Latest inventory stored as the host's current state: stable fields plus volatile fields updated on every report.
  - Dated inventory snapshots created only when the hash of the stable fields changes (including boot id changes, so reboots are visible).
- Normalisation and hostile-input handling: strip control characters, cap string lengths and array sizes, validate address formats, reject absurd values (negative sizes, free greater than total).
- Machine identifier recorded; a credential used from a different machine identifier raises a visible warning on the host (clone detection, FR-S.1).
- Writes audit entries only for notable events (first inventory, machine id mismatch), not for every report.

## Acceptance criteria

- [ ] AC-1.4: the same report sent twice creates one snapshot and one set of rows
- [ ] A new report with unchanged stable fields creates no snapshot but refreshes volatile fields
- [ ] A changed stable field creates a snapshot
- [ ] A report with an unreadable field (null and a warning) is stored with the warning
- [ ] Invalid reports (wrong types, impossible values, oversize) are rejected with no partial write
- [ ] Hostile strings (markup, control characters) are stored safely; rendering is covered in [P1-S12](p1-operability.md)
