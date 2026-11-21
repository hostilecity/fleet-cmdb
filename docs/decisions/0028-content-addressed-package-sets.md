# ADR 0028: Store each distinct package set once, in content-addressed chunks, and match each chunk once

- Status: Accepted (approved by the owner, 2026-11-16; built in #196)
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
- **Chunks share well in every fleet modelled.** A host's set differs from its neighbours' in a few packages, so it differs in a few of its 64 chunks: at one moment, 16 to 2,200 times fewer entry rows than per-host rows today (82 times in the hand-managed fleet), and only 2 to 11 new chunks a day in the 10,000-host template fleet (155 to 574 in the hand-managed one), against 142 to 222 new whole sets. What a retention window keeps is larger; see the next section.
- **Re-matching after an advisory** for one base-image source touches 1 chunk on the homelab, 8 at 10,000 hosts, 15 at 100,000, and 96 in the hand-managed fleet, against every host today.
- The model leaves out sources of variety a real fleet has (packages chosen by configuration management per host, language runtimes, held packages, dependency drift between image versions), so real fleets have more distinct whole sets, not fewer. Chunks are less sensitive to these, since each touches few buckets.

### What a 90-day window keeps, and the bucket count

Garbage collection keeps every set a host, a kept snapshot, or a host's vulnerability evaluation references (the evaluation's since #196 was built: "As built", item 6), so the window holds about 90 days of new sets, and the chunks they use. The review pointed out that the first version of this ADR counted only the sets of one moment. Counted again from the model (mean new sets and new chunks a day over 6 days, times 90, plus those of the moment), with sizes measured on scratch tables: a set row with its 64 chunk ids as a `bigint[]`, its hash index, and a GIN index on the ids is **814 bytes**; as 64 reference rows it would be 5,952 bytes (93 each); a chunk entry is 154.

| 10,000 hosts, 90-day window | Kept sets | Buckets | Kept chunk entries | Total, references as arrays | Total, references as rows |
|---|---|---|---|---|---|
| Template fleet | 16,480 | 16 | 382,889 (59 MB) | about 66 MB | 83 MB |
| | | 32 | 95,954 (15 MB) | about 24 MB | 64 MB |
| | | **64** | 25,499 (4 MB) | **about 17 MB** | 102 MB |
| Hand-managed fleet | 729,110 | 16 | 24.6 M (3.8 GB) | about 4.1 GB | 4.9 GB |
| | | 32 | 3.7 M (570 MB) | about 950 MB | 2.7 GB |
| | | **64** | 551,000 (85 MB) | **about 680 MB** | 4.4 GB |

Against today, for the same fleets: `host_packages` is 1.7 GB, and the kept JSON snapshots at 8.5 KB each are at least another 0.14 GB (template) and 6.2 GB (hand-managed; one per kept set at least). So:

- **The references are stored as an array**, `package_sets.chunk_ids bigint[]` (64 elements, NULL for an empty bucket), with mark-and-sweep garbage collection (decision 7). As rows they would cost more than the entries they save in the hand-managed fleet, as the review found.
- **64 buckets** stay the best of the three in both fleets once references are arrays: fewer buckets make bigger chunks that change more often, and the window keeps every changed one.
- With arrays, the hand-managed fleet stores about 680 MB against 7.9 GB today (12 times less), the template fleet about 17 MB against 1.8 GB.

### Measured on the benchmark seed

`bin/benchmark seed --hosts 20000 --package-hosts 5000` from #188 (merged locally only), with prototype tables built in SQL from the template host's 800 packages: 1,500 variants (1 to 12 sources upgraded, up to 2 tools) and 20,001 hosts spread over them. PostgreSQL 16, default settings, 2 CPUs shared with other agents' suites (load average 4 to 6), so times are rough.

| What | Today | Whole sets | 64 chunks |
|---|---|---|---|
| Bytes a row, with indexes | `host_packages` 198 | entries 187 | chunk entries 154; a set with its 64 chunk ids as an array, 814 |
| Rows for this prototype | 4.0 M (5,001 hosts) | 1.2 M | 29,468 entries in 1,953 chunks |
| A host's package page (50 rows, name order, offset 400) | 0.15 ms | 0.50 ms | 1.36 ms |
| Search with count | 0.90 ms | | 1.06 ms |
| Diff of two sets | | 0.73 ms in SQL (800 against 800) | 11 of 64 chunks differ: 164 rows read instead of 1,600 |
| Find what to re-match for one source | 458 ms (sequential scan; #185, now merged, adds the index) | 26.5 ms (1,495 sets) | 0.08 ms (the chunks); 0.08 ms for the sets containing a chunk (GIN, 50,000 sets); 25 ms to list the 20,001 hosts that have them |

Findings, per host, on the seed's 2.25 million rows:

| Per-host finding row | Bytes a row, with indexes |
|---|---|
| Today's `vulnerability_findings` | 351 |
| Lifecycle only, natural key (decided below) | 178 |
| Lifecycle only, with an id for (advisory, package, architecture) | 114 |

Opening one new finding on 3 binary packages of every host, re-measured as the design runs it, on a scratch database with #206's schema and its statement triggers (1,000 hosts with 450 findings each; load average about 6, so rough):

| How | Time a host |
|---|---|
| One short transaction a host, locking its row (two runs) | 9.6 to 13.5 ms |
| The same with #206's triggers disabled | 5.2 ms |
| **Batches of 100 hosts a transaction, locked in id order** | **1.2 ms** |
| One statement for every host, triggers disabled (the first version's figure) | 0.33 ms |

Most of the per-host cost is #206 recounting each host's summary. So host transitions run in batches, locked in id order, **sized by lock time as #204 sizes CIS evaluation** (`CisEvaluation::LOCK_TARGET`, 0.2 s): the first batch is 100 hosts, and each next one is scaled from the last one's time, so a heartbeat waits about 0.2 s at most however loaded the server is. A fixed 100 hosts would hold 100 host locks for 120 ms here and much longer under load. At a million hosts, an advisory that affects every host costs about **20 minutes** of one worker for the host rows (spread over #204's evaluation workers), not the 38 s the first version claimed from a bulk statement; matching it costs only its chunks. Today it is about 3 hours of matching, before #206's recounts.

## Options considered

| Option | For | Against |
|---|---|---|
| **Content-addressed sets made of 64 content-addressed chunks; match per chunk; per-host lifecycle rows** (chosen) | Shares storage and matching in every fleet modelled; a change copies only the chunks of the sources it touches; matching is exact per package, so per chunk is exact. Snapshots are one small row. | More tables; a bucket function fixed for good; a host's package page reads through its set (about 1 ms more). |
| Distinct package versions: a table of distinct `(ecosystem, name, architecture, version, source)`, one reference row per host and package, verdicts per distinct package version | Simpler: no buckets to fix for good, no sets. Matching is exact and as small (once per distinct version). The package page is about as fast (1.25 ms measured, the same join and sort as chunks). | Still one row per host and package: 83 bytes measured, so 852 packages are 71 KB a host, 71 GB at a million hosts (against 170 GB today and a few GB with chunks). A snapshot must still list every package (852 ids, about 7 KB), so kept snapshots save little against today's 8.5 KB JSON. An advisory's fan-out is the same. It loses on storage, which is the point of #196, by one to two orders of magnitude. |
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
6. **Copy-on-write.** When one package changes on one host, only its bucket's chunk changes; a package whose source changes moves between two buckets, and an update that touches several sources (a kernel ABI bump touches `linux` and `linux-signed-amd64`) changes the chunks of each. Chunk boundaries never shift: a bucket depends only on a package's own source name. The server finds or stores the changed chunks, then finds or stores the set, points the host at it, and writes a small snapshot row. The host's finding rows change only for those chunks' packages.
7. **A host's transitions need every chunk of its set evaluated.** "Stored" is not "matched": a chunk another host brought a moment ago may not be matched yet, and a chunk seen before only in another ecosystem has no verdicts for this one. Without verdicts the host's findings for it would wrongly resolve as `fixed`. So before a host's transitions run, every chunk of its set must have a `chunk_evaluations` row for the host's ecosystem, current with the newest succeeded advisory import for that ecosystem (`advisory_import_id`); any that has none, or an older one, is matched first, in the same job (a chunk is about 13 packages). Two hosts matching the same new chunk at once write the same verdicts, with `INSERT ... ON CONFLICT DO NOTHING`.
   - **What the stamp means:** "this chunk's verdicts are right for the advisory data as of import N". A match reads the newest succeeded import's id **before** it reads the advisory data, so a stamp never claims newer data than was matched.
   - **An import keeps unaffected chunks current.** At its end, after re-matching the chunks with changed sources, it re-stamps, in one set-based `UPDATE`, every evaluation for its ecosystem that was current with the import before it and has no changed source. Without this, every other chunk in use would look stale after each import and be matched again on its next use: a lazy full match after every import (the review's finding).
   - **A dangling chunk id fails closed.** With no foreign keys, a set's `chunk_ids` could hold a chunk that no longer exists (a bug). Treating that bucket as empty would resolve its findings as `removed`, so the host's transitions are refused instead, and the job logs an error that the failed-jobs page shows.
8. **Garbage collection is mark and sweep**, after each retention run. A set is kept if a host, a kept snapshot, or a host's vulnerability evaluation (the set its findings were last moved from, which a resolution reads; added when built, "As built" item 6) references it; a chunk is kept if a kept set's `chunk_ids` holds it; the rest are deleted (a chunk's entries and verdicts cascade). There are no foreign keys from snapshots or sets, so instead every set and chunk has a `last_used_at`: the recorder touches a set or chunk it reuses when that is more than a day old, and collection deletes only rows unreferenced and untouched for two days, re-checking `last_used_at` in the `DELETE`'s own condition. The touch and the delete then conflict on the row: if the touch wins, PostgreSQL re-evaluates the delete's condition on the touched row and skips it; if the delete wins, the touch updates nothing and the recorder stores the chunk again by its hash.

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
  chunk_ids     bigint[] NOT NULL CHECK (cardinality(chunk_ids) = 64),  -- by bucket; NULL for an empty bucket
  package_count integer NOT NULL,
  created_at    timestamp NOT NULL,
  last_used_at  timestamp NOT NULL
);
CREATE INDEX ON package_sets USING gin (chunk_ids);  -- the sets that contain a chunk
-- package_chunks also gets last_used_at timestamp NOT NULL

-- No foreign keys from these to package_sets: package_snapshots is partitioned (ADR 0027), and a key there
-- would lock package_sets on every partition operation; PostgreSQL 16 also refuses NOT VALID keys on a
-- partitioned table, so adding one would scan every partition under lock. Mark and sweep instead.
ALTER TABLE host_package_sets ADD COLUMN package_set_id bigint;  -- NULL: unsupported, or never readable
CREATE INDEX CONCURRENTLY ON host_package_sets (package_set_id);
ALTER TABLE package_snapshots ADD COLUMN package_set_id bigint;  -- replaces packages jsonb; NULL for unsupported and unreadable
-- The sweep's "is this set still kept", built online (see below the DDL)
CREATE INDEX package_snapshots_package_set_id ON ONLY package_snapshots (package_set_id);  -- the parent only; invalid until attached
CREATE INDEX CONCURRENTLY package_snapshots_p20261116_package_set_id ON package_snapshots_p20261116 (package_set_id);  -- each partition
ALTER INDEX package_snapshots_package_set_id ATTACH PARTITION package_snapshots_p20261116_package_set_id;  -- each partition

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
  not_evaluated    jsonb NOT NULL DEFAULT '[]',  -- [{package, architecture, version, source, advisory, reason}]
  advisory_import_id bigint NOT NULL,           -- the newest succeeded import for the ecosystem when matched
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

**Indexing a partitioned table online.** PostgreSQL 16 refuses `CREATE INDEX CONCURRENTLY` on a partitioned table, and a plain `CREATE INDEX` on the parent takes a `SHARE` lock on every partition for the whole build, which blocks package reports (both verified by the review). So the migration creates the index on the parent only (`ON ONLY`, instant, left invalid), builds each partition's index with `CONCURRENTLY`, and attaches each one. The parent's index becomes valid once every partition's is attached, and partitions created later get it automatically. The partition manager doesn't create partitions of this table while the migration runs.

A host's current verdicts, for the pages and for the transitions:

```sql
SELECT hps.host_id, m.*
FROM host_package_sets hps
JOIN host_vulnerability_evaluations e ON e.host_id = hps.host_id AND e.state = 'evaluated'
JOIN package_sets s ON s.id = hps.package_set_id
JOIN LATERAL unnest(s.chunk_ids) AS c(chunk_id) ON true
JOIN chunk_matches m ON m.package_chunk_id = c.chunk_id AND m.ecosystem = e.ecosystem
WHERE hps.host_id = $1;
```

Set-to-chunk references are an array on `package_sets` (814 bytes a set with its indexes), not 64 rows (5,952 bytes), because a window keeps many sets (see the context).

## How matching, the package diff, and the findings lifecycle change

- **A new package report.** As in decision 6, then decision 7's check, then the host's transitions under its row lock: verdict keys that are new for the host open a finding (or reopen a resolved one); active findings whose key is gone resolve as `removed` (the package is not in the set), `fixed` (it is, at a version outside the ranges), `withdrawn`, or `not_affected` (from the advisory), as P2-S11 defines them. A host on a set whose chunks are all evaluated costs no matching at all.
- **Versions dpkg cannot parse.** As today (`vulnerability_matcher.rb`, the `verdict.is_a?(String)` branch), a package and advisory that cannot be evaluated leave the host's finding for them as it is: neither opened nor resolved. Only affected rows are in `chunk_matches`, so before a missing key resolves, it is looked up in the chunk's `not_evaluated` list, and a key listed there is left unchanged.
- **An advisory import.** Changed sources, per ecosystem, give the chunks that contain them (the `COALESCE(source, name)` index), which are matched again and stamped with the import's id. The chunks whose verdicts changed give the sets that contain them (the GIN index), and those the hosts, whose transitions run in batches sized by lock time within the host id ranges that #204's evaluation runs already use. At the end, the import matches again any chunk with a changed source whose `advisory_import_id` is older than its own (a chunk created during the import, matched against the data before it, is not left with stale verdicts), and re-stamps the unaffected ones (decision 7). At 100,000 hosts in the template model, one source is 15 chunks to match instead of 100,000 hosts; the host transitions remain one row per affected host and package (about 1.2 ms a host with #206's triggers, measured above).
- **A full match** (the first import, or "match again") is every distinct chunk once: 3,351 chunks, about 54,000 package verdicts, at 100,000 hosts in the template model, against 85 million package verdicts today.
- **The not-evaluated list** of a host is the union of its chunks' lists, cut at 100 as now.
- **Hosts that cannot be matched** (no inventory, unsupported or unreadable manager, no advisory data) stay "not evaluated" per host from `HostContext`, as now. An unreadable report keeps the host's previous set, as it keeps its rows now; its snapshot has no set (`package_set_id` NULL), as an unreadable snapshot has no list today.
- **The package diff.** `PackageDiff.between` takes two sets: it compares their chunk references, loads entries only for the buckets that differ, and runs today's Ruby comparison (dpkg ordering, skipped names from each snapshot). A diff summary is cached by the pair of set ids instead of snapshot ids: sets never change, and hosts in a template fleet share pairs, so one host's comparison warms the cache for the others.

## How the dashboard changes

Every reader of `host_packages` moves to the host's set:

| Reader | Change |
|---|---|
| Packages tab (`HostPackageList`: search, filters, sort, pages, architectures, "open findings" filter) | Entries through `host_package_sets`, the set's `chunk_ids`, and `package_chunk_entries`; the open-findings filter joins `vulnerability_findings` on host, package, and architecture as now. 1.36 ms a page on the seed, against 0.15 ms. |
| Package comparison and snapshot list (`PackageSnapshotTimeline`) | Snapshots carry set ids; diffs by chunk; summaries cached by set pair. |
| Vulnerabilities tab and package page (`HostVulnerabilitiesController`) | Installed versions and sibling packages from the host's chunk verdicts and entries instead of `host_packages` and the findings' copied versions. |
| "Hosts with this source" (`VulnerabilityMatchJob`, `AdvisoryUploadImportJob#matching`) | Chunks with the source, then sets, then hosts. |
| Fleet list and compliance counts (`FleetCompliance`; ADR 0026's summaries, #206) | Unchanged: they count active findings by host and severity, and the table keeps host, advisory, and state. #206's triggers on `vulnerability_findings` keep working, and they are most of the cost of an advisory's fan-out (measured above). An advisory that changes only versions no longer writes per-host rows, so it no longer recounts every host. |

## Migration from the current schema, online, at a million hosts

Each step is additive or catalog-only; the long work is batched in short transactions.

1. **New tables, empty.** Deploy the recorder writing both: chunks, set, and `package_set_id` as well as `host_packages`. Readers unchanged.
2. **Backfill hosts** in a job, in keyset batches of 1,000 hosts.
   - **Only `manager = 'dpkg'` hosts are grouped.** Hosts with the same `host_package_sets.content_hash` and a `dpkg` manager have the same list, so a set is computed once per distinct hash from one host's rows, and every host with that hash points at it.
   - **An unreadable host's set is built from its own `host_packages` rows.** Its `content_hash` hashes only `("unreadable", reason, [])` (`lib/agent_api/package_report.rb:48`), while `PackageRecorder` keeps that host's previous rows, so every unreadable host with the same reason shares a hash but not a list (the review's blocker). An unsupported host gets no set.
   - A host whose hash changed during the batch is skipped: the recorder already wrote it.
   - **Cost.** The model's fleets have 78 to 96% distinct hashes, so at a million hosts that is up to about 900,000 sets to compute; at about 17 ms each (the prototype, in SQL), about **4.5 hours of one worker**, or about an hour over #204's evaluation workers. It is resumable and holds no long lock.
3. **Backfill the kept snapshots.** Retention keeps each host's newest package snapshot whatever its age (ADR 0007; ADR 0027 moves it forward), so for every host whose packages have not changed since the switch, that snapshot is a JSON-only row that would otherwise be lost (the review's blocker). In the same batched way, every `dpkg` snapshot with a list and no `package_set_id` gets the set of its JSON list (found by hash, or stored). Unsupported and unreadable snapshots have no list and keep no set.
4. **Match the chunks** (every distinct chunk once), then run a check that, for every host, the active findings derived from its chunks are the same keys as its active `vulnerability_findings`, with the same versions, and that unparsable versions are left alone as decided. The old matcher stays as the oracle until the check is clean.
5. **Switch matching and the readers** to sets and chunks; stop writing `host_packages`; snapshots write `package_set_id`. `PackageSnapshot#package_list` reads either until the clean-up.
6. **Clean up**, only once `packages:check_snapshots` reports **no `dpkg` snapshot with neither a set nor a list**: run step 3 again for snapshots written between it and the switch, then `DROP TABLE host_packages` and `DROP COLUMN packages` (both instant). Dropping the derived columns of `vulnerability_findings` is instant too, but the space returns only as rows are rewritten; a large fleet that wants the smaller rows at once rebuilds the table with a batched copy and a swap.

With ADR 0027: convert `package_snapshots` to partitions first, so the new small snapshots are written to the partitioned table; the JSON ones that retention would drop leave with their partitions, and the kept ones are covered by step 3.

## The homelab

No setting, no service, nothing to install. The model's homelab (50 hosts from one image, a few hand-installed tools) keeps 39 distinct sets but only 193 chunks: about 2,700 stored package rows instead of 42,600. A package page reads about 1 ms slower. There are six more tables and the code that keeps them; the owner reading the database by hand finds a host's packages through its set.

## Risks

- **Correctness of derived findings.** Mitigated by the equivalence check in step 4, and by keeping today's matcher as a test oracle on randomised fleets until the switch.
- **More writes for fleets where every set is unique.** A changed report in a fleet like the hand-managed model writes a new set (one 814-byte row) and a chunk (about 13 entries), against about 30 changed rows with #185. Over a 90-day window that fleet stores about 680 MB against 7.9 GB today (12 times less, not the 82 times the first version claimed from one moment's entries).
- **The bucket function is forever.** Changing it re-chunks every set; the chunking version in the hash allows it as a rebuild.
- **Garbage collection racing a report** that reuses a set or chunk: decision 8's touch and its re-checked `DELETE` conflict on the row, so exactly one wins; a spec runs both orders. Without foreign keys, a bug could leave a dangling id; `packages:check_snapshots` reports any.
- **A chunk with stale verdicts** after an import that raced its creation: closed by the end-of-import pass and the stamp read before the data (decision 7); a full "match again" clears anything else.
- **A dangling chunk id** stops that host's transitions with an error rather than resolving findings (decision 7).
- **Per-host finding rows remain the largest table**: 450 findings at 178 bytes is 80 KB a host, 80 GB at a million hosts (from 157 GB). The next steps, if needed, are an id for (advisory, package, architecture) (114 bytes) and later a derived lifecycle, which needs its own decision on P2-S11.
- **Hash collisions** of SHA-256 are not a practical risk.

## How it will be tested and measured

- Property specs: a list stored and read back is the same list; the same list gives the same set id whatever the report order; a change changes only the chunks of the sources it touches (two for a package whose source changes); an empty list and an unsupported manager.
- Matching equivalence on randomised fleets from the fleet simulator: chunk-derived findings, states, and versions equal today's `VulnerabilityMatcher` output, for new reports, advisory imports, withdrawals, unparsable versions (left unchanged), skipped packages, and unreadable reports.
- Race specs: a host whose set has a chunk not yet evaluated (or evaluated only in another ecosystem, or against an older import) gets it matched before its transitions, and no finding resolves; a chunk created during an import is matched again at its end; after an import, chunks without a changed source are current and are not matched again; a dangling chunk id refuses the host's transitions; collection against a touch, in both orders.
- Batch sizing: transition batches hold their host locks for about `LOCK_TARGET`.
- Migration specs: unreadable hosts with the same reason get their own sets; a host's kept JSON-only snapshot gets its set; the clean-up refuses while any `dpkg` snapshot has neither.
- `PackageDiff` equivalence between sets and the JSON lists.
- `bin/benchmark seed` gains `--package-variants` to seed sets with the model's distribution; `queries`, `explain`, and `jobs` report the package report, the packages tab, matching, and an advisory import, before and after.
- 100% line coverage, as now.

## Building it

One issue each; each PR is reviewable alone.

1. **Sets and chunks, written alongside:** the tables, the store (hashing, chunking, find or create, touch), the recorder writing both, the host backfill (dpkg grouped, unreadable from own rows), the benchmark's `--package-variants`.
2. **Readers on sets:** the packages tab, the comparison and snapshot list, the vulnerabilities pages; snapshots store set ids; the snapshot backfill and `packages:check_snapshots`.
3. **Matching per chunk** (after #204): `chunk_matches`, `chunk_evaluations` with the import id, the evaluated-chunks check before transitions, transitions in batches sized by lock time, advisory import by chunk with its end-of-import re-match and re-stamp, the equivalence check; `vulnerability_findings` slimmed.
4. **Clean-up and garbage collection:** drop `host_packages` and the JSON column behind the check; mark-and-sweep collection in the retention job; `docs/operations/agent-packages.md`, and the P2-S08 and P2-S11 texts in the specs.

## As built (#196)

Built as decided, in one pull request. Where the build departs from the text above, or decides what it left open, it is said here; the owner approved the ADR on 2026-11-16, and these points need the owner's OK on the pull request.

1. **One release, not four.** No backward compatibility is needed (NFR-5), so the online, write-both migration (steps 1 to 6, and the four issues of "Building it") is one deploy, with no dual write and no switch: `CreatePackageSets` and `IndexPackageSetReferences` (the tables and columns; the snapshot index built `CONCURRENTLY`, per partition with `ON ONLY` when `package_snapshots` is partitioned by ADR 0027, else on the table; an index left invalid by a failed build is dropped and built again), `BackfillPackageSets` (steps 2 and 3, `PackageStoreBackfill`), and `DropHostPackages` (step 6, refusing while any dpkg snapshot or host has no set or any finding has no copied details; it waits at most 10 s for its locks).
   - **What it costs.** The backfill is one keyset pass over temporary partial indexes on `content_hash` (dropped at the end), so it is linear: per distinct package list (a host's current one or a kept snapshot) it reads one row, stores the set through `PackageStore` (so it hashes as a report's would), and updates the rows with that hash. Measured on a `main`-seeded database with 100,000 distinct snapshots (each list differing from the next in one package, so each stores one new chunk), on 2 shared CPUs: 15 ms a list on a quiet machine to 31 ms under load (load average 4 to 9), the same from the first 10,000 lists to the last; 100,000 took 52 minutes loaded. So about 25 to 50 minutes for 100,000 distinct snapshots and 4 to 9 hours for 1,000,000, on one worker. The findings copy took about 10 s for 100,000 rows. If ADR 0027's partitions land first, each per-hash lookup and update probes every partition's temporary index (a dozen or so), still linear. Findings' details are copied in keyset batches of 10,000 rows.
   - **Where it runs.** At container start (`db:prepare`) when its estimate is small: `PackageStoreBackfill#estimate` at most 90 s. The estimate adds 30 ms for each distinct list and 0.02 ms for each package in them (read and hashed), 0.18 ms for each package of each distinct chunk of the lists to move, stored or not (every package when that still fits, otherwise the packages of the distinct chunks, counted in SQL with PackageStore's buckets for at most 30 s), 0.1 ms per snapshot or host row, and 0.12 ms per finding. It counts in that order and stops once past the limit, so it reads only part of a large database. The rates are about three times those measured on a quiet 2-CPU machine. Two reviews shaped it. The first version counted lists and findings only, and the review of #240 fooled it both ways: 500 distinct lists of 3,000 packages took about 116 s, and 400,000 rows over 20 lists about 11 s. The second charged every package as new, and the review of #250 found that it refused a varied 50-host homelab (700 lists, 581,000 packages) that took 9 s; it also found that findings with sparse ids (after retention) took 294 s, because the copy stepped over id ranges, so the copy now walks the ids by keyset. Measured since: that homelab 12 s (estimate 39 s), the sparse findings 5 s (36 s), the 400,000 rows 8.7 s (41 s), and the 500 large lists 92 s (315 s, refused), all under a load average of about 1; under 9 to 11 the last two took 38 s and 302 s (`docs/operations/upgrades.md` has every case). Earlier, near the old limit on a `main`-seeded database (2,002 lists and 225,450 findings) under a load average of 8, the backfill took 62 s, and the boot with every migration 66 s, against the deploy's 300 s wait for `/up`. Above the limit it refuses before changing anything, with a line starting `fleet-cmdb upgrade step needed:` and the runbook's command; `bin/docker-entrypoint` then keeps the container up without serving instead of exiting (it stops at once on SIGTERM), so it does not restart into the refusal. The operator runs `ops/backup/package-backfill.sh` (installed as `~/.local/share/fleet-cmdb/backup/package-backfill.sh`), with the Deploy workflow disabled: it takes the backup lock with #236's own `take_lock` (from `ops/backup/lock.sh`, shared with `docker.sh`), refuses during a restore or while the restore-incomplete marker exists, runs `bin/rails packages:backfill` (resumable; a second one at once refuses) in the waiting container, restarts it and holds the lock until `/up` answers on 3000 and 3443. Interrupted during the backfill, it stops it and does not restart the app; interrupted during the `/up` wait, it keeps waiting and the lock, and only a second interrupt releases it while the migrations may run; a crash-looping, stopped or refusing app ends the wait at once; after 30 minutes without `/up` it releases the lock although the migrations may still run (`docs/operations/upgrades.md`). **The dashboard and the agent API are down for the whole step:** hours at a million distinct snapshots. Agents do not replay what they missed; they send their current state when the server is back.
   - **On partitioned snapshots (ADR 0027, merged first).** The snapshot index is built per partition (`ON ONLY` on the parent, `CONCURRENTLY` on each partition, then attached); the backfill's temporary index is created on the parent, so on every partition, and each per-hash lookup and update probes them all. Re-measured on a `main`-seeded database with partitioned snapshots: the inline case (2,002 lists and 225,450 findings, the same 87 s estimate) took 107 s with the boot and every migration under a load average of 10 to 13, every partition's index valid; with 100,000 distinct snapshots the migration refused (an estimate of 51 minutes) and `packages:backfill` stored 28 ms a list (44 ms while the test suite ran beside it), constant through the run, so about 47 minutes for 100,000, the same rate as before partitioning.
   - **The old space stays.** The dropped columns' space returns only as rows are rewritten: an upgraded database keeps findings rows the size they were (a fresh one gets the smaller rows), and `package_snapshots` keeps its JSON's space (822 MB for the 100,000 above), until the tables are rebuilt or, for snapshots, retention drops them.
2. **Step 4's check is a spec, and matching after the migration is lazy.** The equivalence is a spec that runs `main`'s matcher, ported to keep its findings in memory (`spec/support/legacy_vulnerability_matcher.rb`), beside the chunk matcher on a fleet with epochs, tildes, unparsable versions, multi-arch, two binaries of one source, and through reports and imports, and compares every finding, resolved ones too, with its details; not a run against production data before a switch. After the migration no chunk is matched yet: findings keep the state the old matcher gave them, show their copied details (`last_*`), and each host's chunks are matched at its next transitions (decision 7's check), or all at once with `bin/rails vulnerabilities:match`.
3. **The stamp is the newest stamping import**, in commit order (`finished_at`), not per ecosystem, and "current" means equal to it. Every succeeded import stamps but a feed refresh the server answered "not modified", which changes no data and is written outside the import lock (`AdvisoryImport.stamping`; re-review of #240). An import can change an ecosystem's advisories without listing that ecosystem (an advisory that stops naming its packages), and an upload's import row has an id from when it was queued, so per-ecosystem stamps or ids compared by size could call a stale chunk current. **The re-stamp** (`VulnerabilityMatcher::Chunks.restamp!`, at each import's run) moves an evaluation stamped with any older import to the newest when every stamping import committed since its stamp changed none of its sources; each import records what it changed (`advisory_imports.changed_packages`), and the re-stamp reads only the imports since the oldest stamp still in use. So it holds when an earlier import's run was superseded and never prepared, or when runs prepare out of order (review of #240). An import from before this change has no record, and nothing is moved across it. A match that read an older stamp and then waited for the lock leaves a chunk stamped with a newer import alone.
4. **An import's run takes the hosts on every set holding a chunk with a changed source**, not only the chunks whose verdicts changed. A host's own report can match such a chunk again between the import's commit and its run; its verdict change would then not be seen, and the other hosts on that chunk would keep stale findings. Transitions that change nothing write nothing, so the cost is reads (measured in the pull request).
5. **No separate end-of-import pass.** The run finds its chunks and hosts after the import commits, and every host's transitions first match any chunk of its set whose stamp is not the newest import (decision 7's check, by equality), so a chunk matched against the data before the import is matched again before any host uses it.
6. **`last_source` and `last_ecosystem` too, kept as `main` showed them.** The data model has `last_installed_version` and `last_fixed_version`, set when resolved. The build adds `last_source` (a resolved finding's source package is shown, searched, and joined to Debian's triage, and a removed package is in no chunk) and `last_ecosystem` (written when a finding is created, as `main` wrote `ecosystem`, so a resolved finding keeps its own release after the host moves to another). An active finding shows its live verdict (`VulnerabilityFinding.with_details`), except its fixed version, which since VT-FIXABLE (#256, ADR 0032 point 8) is read from `last_fixed_version`; an open finding has a fix exactly when it is set, which the summaries count, so every page reads the same stored fix. Its source and fix are written whenever its verdict's differ (normally by the run of the import that moved its fix while it is open; a host's own report can write it too, when that run did not reach the host, for example because it was superseded), so the `last_*` values are the last ones known. A resolution takes its details from the finding's verdict in the set the host's findings were last moved from (`host_vulnerability_evaluations.package_set_id`, which garbage collection keeps): the source the advisory matched, the last installed version (the one installed now, if any), and the last fix. The equivalence spec compares every finding, resolved ones included, with `main`'s matcher, and they are equal.
7. **Transitions always cover the whole set.** There is no targeted run for an import's sources: a host's transitions read its chunks' verdicts, so a full pass costs reads, keeps the not-evaluated count exact, and removes the targeted-run special cases.
8. **The diff summary cache key** is the pair of set ids plus, when either snapshot names any, a digest of both snapshots' skipped names: the skipped names change the diff, and they are per snapshot, not per set.
9. **Garbage collection runs in `RetentionPruneJob`** (daily), after `Retention.prune!`, not inside `Retention`. Since ADR 0027, snapshots past the window leave by whole partitions in the hourly `PartitionMaintenanceJob`; the next collection finds the sets they alone referenced, two days after their last use. `bin/rails packages:check_snapshots` reports dpkg snapshots and hosts with no set and ids that name nothing.
10. **Two matches of one chunk are serialised** by a transaction-level advisory lock per chunk and ecosystem, taken in chunk id order, and each re-checks under it whether the chunk is current, instead of both writing with `INSERT ... ON CONFLICT DO NOTHING`: a re-match after an import replaces verdicts, which `DO NOTHING` cannot. `chunk_evaluations` also has an index on `(advisory_import_id, ecosystem)` for the re-stamp.
11. **The benchmark's `--package-variants N`** spreads the package hosts over N sets derived from the template's as this ADR's prototype did (1 to 12 sources upgraded, up to 2 tools), not over the fleet model's distribution, which is not in the repository. It is the favourable case (a template fleet); the hand-managed model, where most sets are distinct, is not measured.

## Consequences

- Package storage grows with the sets and chunks a window keeps, not with hosts times packages: 12 to 100 times less than today in the 10,000-host models over a 90-day window, snapshots included.
- Matching cost grows with new chunks, not with hosts; an advisory's per-host cost is its finding rows and #206's recount, about 1.2 ms a host in batches sized by lock time.
- Whole-set sharing is not the saving: a fleet "built from one image" still has many distinct sets. The design does not depend on fleets being uniform.
- The per-host findings lifecycle is the remaining per-host store, and the next limit.
