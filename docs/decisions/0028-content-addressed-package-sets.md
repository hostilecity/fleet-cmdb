# ADR 0028: Store each distinct package set once, in content-addressed chunks, and match each chunk once

- Status: Proposed (#196; needs the owner's OK)
- Decision issue: #196
- Requirements: `FR-2.3`, `FR-2.4`, `FR-2.5`, `NFR-3`; P2-S08 ([p2-packages.md](../backlog/specs/p2-packages.md)), P2-S11 ([p2-vulns.md](../backlog/specs/p2-vulns.md))
- Extends: [ADR 0011](0011-vulnerability-data.md) (matching on source package with dpkg ordering) and [ADR 0007](0007-snapshots-and-retention.md) (a package snapshot whenever the set changes). Neither is reversed: what is matched, what a finding is, and when a snapshot is written stay the same. Only storage and the unit of matching change.
- Agent contract: unchanged. This is server-side only; no agent release is needed.

## Context

- `host_packages` holds one row per package per host: **198 bytes a row** with its indexes (benchmark seed, #188). A Debian server has 500 to 2,000 packages, so a million hosts is 0.8 to 2 billion rows, 170 to 400 GB.
- `package_snapshots` store the whole list as JSON on every change: **8.5 KB a snapshot** for 800 packages, TOAST-compressed.
- Matching works host by host: 59 ms a host in production mode (P-11), so a full match of a million hosts is 16 hours, and an advisory for a package on every host re-matches every host: 10.6 ms a host, 3 hours (assessment, P-08 and P-11).
- `vulnerability_findings` holds one row per finding per host: **351 bytes a row**. The seed's template host has 450 findings, so a million such hosts is 157 GB.
- Fleets built from templates share most of their packages. How many *distinct* sets they have decides how much a shared store saves, and the issue assumed "a handful". The model below says that assumption is wrong for whole sets, and right for parts of sets.

### How many distinct sets a fleet has (synthetic model)

The benchmark seed copies one host, so every host has the same set; it cannot answer this. A small model (Python, not in this PR) simulates 180 days of a fleet. Its inputs are stated assumptions, not measurements of a real fleet:

- the benchmark's base image (300 source packages, 800 binary packages), role packages from a pool of 400 sources (5 to 40 per role), 20 hand-installed tools (each host has each with probability q), and the kernel, whose package name changes with each ABI bump;
- security updates (each source about once in 100 weeks, about 3 a week across the base image), point releases every 8 weeks (15% of sources), a kernel ABI bump every 5 weeks;
- security updates installed by unattended-upgrades (the next 06:00 run with its 60-minute random delay, after a download within 12 hours); other updates by the operator's patch cycle (one patch day for the whole fleet, four weekly rings, or each host on its own day); a share of lagging hosts (off, or upgrades disabled) that catch up about every 30 days; a host keeps the kernel it booted until its next reboot.

Counted at 06:30 and 12:00 each day over the last 28 days (14 for 100,000 hosts). A **chunk** is the part of a set whose source package names hash to one of 64 buckets (the decision below).

| Fleet in the model | Hosts | Distinct whole sets: median (min to max) | Of which one host only | New sets a day: median (max) | Distinct chunks | Rows stored: per host today / whole sets / chunks |
|---|---|---|---|---|---|---|
| Homelab template: 3 roles, tools at 5%, one patch day | 50 | 39 (36 to 44) | 34 | 4 (41) | 193 | 42,609 / 35,761 / 2,652 |
| Strict homelab template: no hand-installed tools | 50 | 6 (3 to 17) | 1 | 3 (11) | 117 | 42,558 / 5,113 / 1,577 |
| Template fleet: 20 roles, tools at 2%, 4 rings | 10,000 | 1,465 (1,186 to 2,153) | 876 | 160 (222) | 1,133 | 8.5 M / 1.0 M / 17,584 |
| Template fleet: 50 roles | 100,000 | 11,260 (7,733 to 38,004) | 7,266 | 2,254 (176,795) | 3,351 | 85 M / 6.7 M / 54,456 |
| Strict template fleet: no tools, weekly reboots | 100,000 | 658 (584 to 25,520) | 484 | 549 (175,118) | 2,514 | 85 M / 0.5 M / 39,123 |
| Hand-managed: 500 roles, each host patched on its own day | 10,000 | 9,560 (9,392 to 9,883) | 9,213 | 8,879 (11,704) | 6,241 | 8.6 M / 8.3 M / 104,713 |

What this says, honestly:

- **Whole sets share well only in a strictly uniform fleet.** One hand-installed tool, a kernel still waiting for a reboot, or a host halfway through a rollout makes the whole set distinct. The owner's homelab, cloned from one image, still has 39 distinct sets among 50 hosts once a few hosts have an extra tool; a hand-managed fleet is 96% distinct. The maximum column is a rollout in progress: on a point-release day nearly every host passes through a set no other host has.
- **Chunks share well in every fleet modelled.** A host's set differs from its neighbours' in a few packages, so it differs in a few of its 64 chunks: 16 to 2,200 times fewer rows than per-host rows today (82 times in the hand-managed fleet), and only 2 to 11 new chunks a day in the 10,000-host template fleet (155 to 574 in the hand-managed one), against 142 to 222 new whole sets.
- **Re-matching after an advisory** for one base-image source touches 1 chunk on the homelab, 8 at 10,000 hosts, 15 at 100,000, and 96 in the hand-managed fleet, against every host today.
- The model leaves out sources of variety a real fleet has (packages chosen by configuration management per host, language runtimes, held packages, dependency drift between image versions), so real fleets have more distinct whole sets, not fewer. Chunks are less sensitive to these, since each touches few buckets.
- **Bucket count** (10,000-host template fleet): 16 buckets store 109,512 rows (2,037 chunks), 64 store 17,584 (1,133), 256 store 4,641 (905). 64 is the knee: past it, the 256 references a set needs cost more than the rows they save.

### Measured on the benchmark seed

`bin/benchmark seed --hosts 20000 --package-hosts 5000` from #188 (merged locally only), with prototype tables built in SQL from the template host's 800 packages: 1,500 variants (1 to 12 sources upgraded, up to 2 tools) and 20,001 hosts spread over them. PostgreSQL 16, default settings, 2 CPUs shared with other agents' suites (load average 4 to 6), so times are rough.

| What | Today | Whole sets | 64 chunks |
|---|---|---|---|
| Bytes a row, with indexes | `host_packages` 198 | entries 187 | chunk entries 154; set-to-chunk rows 93 |
| Rows for this prototype | 4.0 M (5,001 hosts) | 1.2 M | 29,468 entries in 1,953 chunks, 96,000 set-to-chunk rows |
| A host's package page (50 rows, name order, offset 400) | 0.15 ms | 0.50 ms | 1.36 ms |
| Search with count | 0.90 ms | | 1.06 ms |
| Diff of two sets | | 0.73 ms in SQL (800 against 800) | 11 of 64 chunks differ: 164 rows read instead of 1,600 |
| Find what to re-match for one source | 458 ms (sequential scan; #185 adds the index) | 26.5 ms (1,495 sets) | 0.08 ms (the chunks), 25 ms to list the 20,001 hosts that have them |

Findings, per host, on the seed's 2.25 million rows:

| Per-host finding row | Bytes a row, with indexes |
|---|---|
| Today's `vulnerability_findings` | 351 |
| Lifecycle only, natural key (decided below) | 178 |
| Lifecycle only, with an id for (advisory, package, architecture) | 114 |

Opening one new finding on 3 binary packages of every host (60,000 rows, one statement): **0.76 s**, 12.6 µs a row; at a million hosts, about 38 s, against about 3 hours of per-host matching today.

## Options considered

| Option | For | Against |
|---|---|---|
| **Content-addressed sets made of 64 content-addressed chunks; match per chunk; per-host lifecycle rows** (chosen) | Shares storage and matching in every fleet modelled; a one-package change copies one chunk; matching is exact per package, so per chunk is exact. | More tables; a host's package page reads through its set (about 1 ms more). |
| Whole sets only, as the issue proposed | Simplest shared store. | Saves little unless the fleet is strictly uniform (39 of 50 sets distinct on the homelab model); any change copies the whole set. |
| A set as a base set plus a delta | Small per host. | Deltas chain or must be rebased; diffs and matching must replay them; no sharing between hosts that drift the same way. |
| Keep `host_packages`, match per distinct set only | No storage change. | Storage stays 170 to 400 GB at a million hosts. |
| No per-host finding rows: derive the lifecycle from each host's set history | Smallest. | When a finding was first seen is per host and must survive set changes; derived from snapshot history, it is lost when snapshots are pruned (a host whose package stayed vulnerable for longer than the window would show it as new). That changes P2-S11's lifecycle and needs its own decision. |
| Per-host lifecycle in one array row per host | About 10 times smaller than rows. | Any change rewrites the whole row (about 5 KB): an advisory touching every host writes gigabytes of WAL; no index for "hosts with this finding". |

## Decision

1. **A chunk** is the entries of one set whose `COALESCE(source, name)` falls in one of 64 buckets (the first two bytes of the SHA-256 of that name, mod 64). Its hash is the SHA-256 of a chunking version, the bucket, and its sorted entries (name, architecture, version, source). **Each distinct chunk is stored once.**
2. **A set** is the list of its non-empty chunks. Its hash is the SHA-256 of the chunk hashes in bucket order. **Each distinct set is stored once**, and **each host points at its set** (`host_package_sets.package_set_id`). A package snapshot stores the set's id, not the JSON list.
3. The normalised list is what is hashed: the report's packages, sorted, as `PackageReport` already sorts them for its content hash. The manager, its reason, skipped names, and warnings stay per host, on `host_package_sets` and on the snapshot, as now.
4. **Matching runs once per distinct chunk and ecosystem.** A package's verdict depends only on its version, its source, the ecosystem, and the advisory data, never on the other packages, so a chunk's verdicts are exact for every host that has it. A host's current findings are the verdicts of its set's chunks, for its ecosystem (from its inventory, `HostContext`, as now).
5. **Per-host state is the lifecycle only**: `vulnerability_findings` keeps its name and its key (host, advisory, package, architecture) and its state, resolution, first seen, resolved at, and reopened at. Versions and sources move to the chunk verdicts. This keeps per host only what differs per host: when this host first had the finding, and whether it resolved and came back. When the host changes set, or a chunk's verdicts change, only that host's affected rows are written.
6. **Copy-on-write.** When one package changes on one host, only its bucket's chunk changes. The server finds or stores that one chunk, then finds or stores the set (64 references), points the host at it, and writes a small snapshot row. If the chunk is new, matching runs for that chunk only (about 13 packages); if another host already brought it, nothing is matched. The host's finding rows change only for that chunk's packages.
7. **Garbage collection** after each retention run: sets no host and no kept snapshot references, then chunks no set references, are deleted (their entries and verdicts cascade). Foreign keys guard every reference, anything created in the last day is skipped, and a recorder that loses a race to a deletion retries once.

## Data model

```sql
CREATE TABLE package_chunks (
  id            bigserial PRIMARY KEY,
  bucket        smallint NOT NULL CHECK (bucket BETWEEN 0 AND 63),
  content_hash  bytea NOT NULL UNIQUE,  -- SHA-256 of chunking version, bucket, sorted entries
  package_count integer NOT NULL,
  created_at    timestamp NOT NULL
);
CREATE TABLE package_chunk_entries (
  package_chunk_id bigint NOT NULL REFERENCES package_chunks ON DELETE CASCADE,
  name             varchar(128) NOT NULL,
  architecture     varchar(32) NOT NULL,
  version          varchar(256) NOT NULL,
  source           varchar(128),
  PRIMARY KEY (package_chunk_id, name, architecture)
);
CREATE INDEX ON package_chunk_entries ((COALESCE(source, name)), package_chunk_id);

CREATE TABLE package_sets (
  id            bigserial PRIMARY KEY,
  content_hash  bytea NOT NULL UNIQUE,  -- SHA-256 of the chunk hashes in bucket order
  package_count integer NOT NULL,
  created_at    timestamp NOT NULL
);
CREATE TABLE package_set_chunks (
  package_set_id   bigint NOT NULL REFERENCES package_sets ON DELETE CASCADE,
  bucket           smallint NOT NULL,
  package_chunk_id bigint NOT NULL REFERENCES package_chunks,  -- RESTRICT: a used chunk is never deleted
  PRIMARY KEY (package_set_id, bucket)
);
CREATE INDEX ON package_set_chunks (package_chunk_id);

ALTER TABLE host_package_sets ADD COLUMN package_set_id bigint REFERENCES package_sets;  -- NULL: unsupported, or never readable
CREATE INDEX ON host_package_sets (package_set_id);
ALTER TABLE package_snapshots ADD COLUMN package_set_id bigint REFERENCES package_sets;  -- replaces packages jsonb

-- Matching's verdicts, once per chunk and ecosystem: only what is affected
CREATE TABLE chunk_matches (
  package_chunk_id  bigint NOT NULL REFERENCES package_chunks ON DELETE CASCADE,
  ecosystem         varchar(64) NOT NULL,
  advisory_id       bigint NOT NULL REFERENCES advisories,
  package           varchar(128) NOT NULL,
  architecture      varchar(32) NOT NULL,
  source            varchar(128) NOT NULL,
  installed_version varchar(256) NOT NULL,
  fixed_version     varchar(256),
  PRIMARY KEY (package_chunk_id, ecosystem, advisory_id, package, architecture)
);
-- Which chunks are matched for an ecosystem, and what could not be evaluated (versions dpkg cannot parse)
CREATE TABLE chunk_evaluations (
  package_chunk_id bigint NOT NULL REFERENCES package_chunks ON DELETE CASCADE,
  ecosystem        varchar(64) NOT NULL,
  not_evaluated    jsonb NOT NULL DEFAULT '[]',
  evaluated_at     timestamp NOT NULL,
  PRIMARY KEY (package_chunk_id, ecosystem)
);

-- Per-host lifecycle: same table and key; derived columns go
ALTER TABLE vulnerability_findings
  DROP COLUMN source, DROP COLUMN ecosystem, DROP COLUMN installed_version, DROP COLUMN fixed_version,
  ADD COLUMN last_installed_version varchar(256),  -- set when resolved: the version it had then
  ADD COLUMN last_fixed_version varchar(256);
DROP INDEX index_vulnerability_findings_on_host_id_and_source;

DROP TABLE host_packages;  -- at the end of the migration
```

A host's current verdicts, for the pages and for the transitions:

```sql
SELECT hps.host_id, m.*
FROM host_package_sets hps
JOIN host_vulnerability_evaluations e ON e.host_id = hps.host_id AND e.state = 'evaluated'
JOIN package_set_chunks sc ON sc.package_set_id = hps.package_set_id
JOIN chunk_matches m ON m.package_chunk_id = sc.package_chunk_id AND m.ecosystem = e.ecosystem
WHERE hps.host_id = $1;
```

Set-to-chunk references are rows, not an array on `package_sets`, so that a foreign key protects every chunk in use from garbage collection. They cost 64 rows a new set (about 6 KB): 67 MB for the 100,000-host template fleet's 11,260 sets.

## How matching, the package diff, and the findings lifecycle change

- **A new package report.** As in decision 6. Then the host's transitions, in its own short transaction under its row lock, as today: verdict keys that are new for the host open a finding (or reopen a resolved one); active findings whose key is gone resolve as `removed` (the package is not in the set), `fixed` (it is, at a version outside the ranges), `withdrawn`, or `not_affected` (from the advisory), as P2-S11 defines them. A host on a set that is already matched costs no matching at all.
- **An advisory import.** Changed sources, per ecosystem, give the chunks that contain them (the `COALESCE(source, name)` index), which are matched again. The chunks whose verdicts changed give the sets that contain them, and those the hosts, whose transitions run in the batches of host id ranges that #204's evaluation runs already use. At 100,000 hosts in the template model, one source is 15 chunks to match instead of 100,000 hosts; the host transitions remain one row per affected host and package (38 s for 3 packages on a million hosts, measured above).
- **A full match** (the first import, or "match again") is every distinct chunk once: 3,351 chunks, about 54,000 package verdicts, at 100,000 hosts in the template model, against 85 million package verdicts today.
- **The not-evaluated list** of a host is the union of its chunks' lists, cut at 100 as now.
- **Hosts that cannot be matched** (no inventory, unsupported or unreadable manager, no advisory data) stay "not evaluated" per host from `HostContext`, as now. An unreadable report keeps the host's previous set, as it keeps its rows now.
- **The package diff.** `PackageDiff.between` takes two sets: it compares their chunk references, loads entries only for the buckets that differ, and runs today's Ruby comparison (dpkg ordering, skipped names from each snapshot). A diff summary is cached by the pair of set ids instead of snapshot ids: sets never change, and hosts in a template fleet share pairs, so one host's comparison warms the cache for the others.

## How the dashboard changes

Every reader of `host_packages` moves to the host's set:

| Reader | Change |
|---|---|
| Packages tab (`HostPackageList`: search, filters, sort, pages, architectures, "open findings" filter) | Entries through `host_package_sets`, `package_set_chunks`, `package_chunk_entries`; the open-findings filter joins `vulnerability_findings` on host, package, and architecture as now. 1.36 ms a page on the seed, against 0.15 ms. |
| Package comparison and snapshot list (`PackageSnapshotTimeline`) | Snapshots carry set ids; diffs by chunk; summaries cached by set pair. |
| Vulnerabilities tab and package page (`HostVulnerabilitiesController`) | Installed versions and sibling packages from the host's chunk verdicts and entries instead of `host_packages` and the findings' copied versions. |
| "Hosts with this source" (`VulnerabilityMatchJob`, `AdvisoryUploadImportJob#matching`) | Chunks with the source, then sets, then hosts. |
| Fleet list and compliance counts (`FleetCompliance`; #206's summaries) | Unchanged: they count active findings by host and severity, and the table keeps host, advisory, and state. #206's triggers on `vulnerability_findings` keep working; an advisory that changes only versions no longer writes per-host rows, so it no longer recounts every host. |

## Migration from the current schema, online, at a million hosts

Each step is additive or catalog-only; the long work is batched in short transactions.

1. **New tables, empty.** Deploy the recorder writing both: chunks, set, and `package_set_id` as well as `host_packages`. Readers unchanged.
2. **Backfill** in a job, in keyset batches of 1,000 hosts. Hosts with the same `host_package_sets.content_hash` have the same list, so a set is computed once per distinct hash from one host's rows, and every host with that hash is pointed at it. A host whose hash changed during the batch is skipped: the recorder already wrote it. At 1,000,000 hosts with 10% distinct hashes, about 100,000 sets to compute; the prototype built a set in about 17 ms of SQL, so about half an hour of one worker.
3. **Match the chunks** (every distinct chunk once), then run a check that, for every host, the active findings derived from its chunks are the same keys as its active `vulnerability_findings`, with the same versions. The old matcher stays as the oracle until the check is clean.
4. **Switch matching and the readers** to sets and chunks; stop writing `host_packages`; snapshots write `package_set_id`. Old snapshots keep their JSON until they are pruned (one retention window; with ADR 0027, when their legacy partition is dropped), and `PackageSnapshot#package_list` reads either.
5. **Clean up:** `DROP TABLE host_packages` and `DROP COLUMN packages` (both instant). Dropping the derived columns of `vulnerability_findings` is instant too, but the space returns only as rows are rewritten; a large fleet that wants the smaller rows at once rebuilds the table with a batched copy and a swap.

With ADR 0027: convert `package_snapshots` to partitions first, so the new small snapshots are written to the partitioned table and the JSON ones leave with the legacy partition.

## The homelab

No setting, no service, nothing to install. The model's homelab (50 hosts from one image, a few hand-installed tools) keeps 39 distinct sets but only 193 chunks: about 2,700 stored package rows instead of 42,600. A package page reads about 1 ms slower. There are six more tables and the code that keeps them; the owner reading the database by hand finds a host's packages through its set.

## Risks

- **Correctness of derived findings.** Mitigated by the equivalence check in step 3, and by keeping today's matcher as a test oracle on randomised fleets until the switch.
- **More writes for fleets where every set is unique.** A changed report in a fleet like the hand-managed model writes a new set (1 row and 64 references) and a chunk (about 13 entries), against about 30 changed rows with #185. Storage still falls 82 times in that model.
- **The bucket function is forever.** Changing it re-chunks every set; the chunking version in the hash allows it as a rebuild.
- **Garbage collection racing a report** that reuses a chunk: foreign keys refuse the deletion or the insert, the one-day grace period makes it rare, and the recorder retries once.
- **Per-host finding rows remain the largest table**: 450 findings at 178 bytes is 80 KB a host, 80 GB at a million hosts (from 157 GB). The next steps, if needed, are an id for (advisory, package, architecture) (114 bytes) and later a derived lifecycle, which needs its own decision on P2-S11.
- **Hash collisions** of SHA-256 are not a practical risk.

## How it will be tested and measured

- Property specs: a list stored and read back is the same list; the same list gives the same set id whatever the report order; a change of one package changes one chunk; an empty list and an unsupported manager.
- Matching equivalence on randomised fleets from the fleet simulator: chunk-derived findings, states, and versions equal today's `VulnerabilityMatcher` output, for new reports, advisory imports, withdrawals, unparsable versions, skipped packages, and unreadable reports.
- `PackageDiff` equivalence between sets and the JSON lists.
- `bin/benchmark seed` gains `--package-variants` to seed sets with the model's distribution; `queries`, `explain`, and `jobs` report the package report, the packages tab, matching, and an advisory import, before and after.
- 100% line coverage, as now.

## Building it

One issue each; each PR is reviewable alone.

1. **Sets and chunks, written alongside** (after #185): the tables, the store (hashing, chunking, find or create), the recorder writing both, the backfill job, the benchmark's `--package-variants`.
2. **Readers on sets:** the packages tab, the comparison and snapshot list, the vulnerabilities pages; snapshots store set ids.
3. **Matching per chunk** (after #204): `chunk_matches`, `chunk_evaluations`, host transitions, advisory import by chunk, the equivalence check; `vulnerability_findings` slimmed.
4. **Clean-up and garbage collection:** drop `host_packages` and the JSON column; the garbage-collection pass in the retention job; `docs/operations/agent-packages.md`, and the P2-S08 and P2-S11 texts in the specs.

## Consequences

- Package storage grows with the number of distinct chunks, not with hosts times packages: in the 100,000-host template model, 54,456 entry rows instead of 85 million.
- Matching cost grows with new chunks, not with hosts; an advisory's per-host cost is one row write for each host it affects.
- Whole-set sharing is not the saving: a fleet "built from one image" still has many distinct sets. The design does not depend on fleets being uniform.
- The per-host findings lifecycle is the remaining per-host store, and the next limit.
