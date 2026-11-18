# Content-addressed package sets and per-chunk matching (#196, ADR 0028, P2-S08, P2-S11): the new tables, empty, and the
# columns that point at them. The data moves in BackfillPackageSets, and the old storage goes in DropHostPackages.
#
# - package_chunks: the entries of one set whose COALESCE(source, name) falls in one of 64 buckets, stored once by the
#   SHA-256 of the chunking version, the bucket, and the sorted entries (PackageStore). package_chunk_entries holds
#   them, indexed by source package so an advisory import finds the chunks it changes.
# - package_sets: a set as its 64 chunk ids in bucket order (NULL for an empty bucket), stored once by the SHA-256 of
#   its chunk hashes. The GIN index finds the sets that hold a chunk.
# - chunk_matches and chunk_evaluations: matching's verdicts once per chunk and ecosystem, and which chunks are
#   matched, against which advisory import, with what could not be evaluated.
# - host_package_sets.package_set_id and package_snapshots.package_set_id: no foreign keys (ADR 0028, the data model:
#   package_snapshots is to be partitioned, ADR 0027); garbage collection is mark and sweep. Their indexes are built
#   concurrently by IndexPackageSetReferences.
# - vulnerability_findings.last_*: the details a finding had at its last transition (source, versions, ecosystem),
#   shown once it is resolved. The derived columns go in DropHostPackages.
# - host_vulnerability_evaluations.package_set_id: the set the host's findings were last moved from, so a resolution
#   can take the details its finding had in that set (its last installed version, source, and fix).
# - advisory_imports.changed_packages: the source packages each import changed, by ecosystem, so an import's re-matching
#   can tell which chunks no import since their stamp has touched (ADR 0028 decision 7). NULL for imports before this.
#
# Every table is new and empty, so this holds no lock on a large table but for the instant ADD COLUMNs.
class CreatePackageSets < ActiveRecord::Migration[8.1]
  def change
    create_table :package_chunks do |t|
      t.integer :bucket, limit: 2, null: false
      t.binary :content_hash, null: false
      t.integer :package_count, null: false
      t.datetime :created_at, null: false
      t.datetime :last_used_at, null: false
      t.index :content_hash, unique: true
      t.check_constraint "bucket BETWEEN 0 AND 63", name: "package_chunks_bucket_valid"
    end

    create_table :package_chunk_entries, primary_key: %i[package_chunk_id name architecture] do |t|
      t.references :package_chunk, null: false, index: false, foreign_key: { on_delete: :cascade }
      t.string :name, limit: 128, null: false
      t.string :architecture, limit: 32, null: false
      t.string :version, limit: 256, null: false
      t.string :source, limit: 128
      t.index "(COALESCE(source, name)), package_chunk_id", name: "index_package_chunk_entries_on_source_package"
    end

    create_table :package_sets do |t|
      t.binary :content_hash, null: false
      t.bigint :chunk_ids, array: true, null: false
      t.integer :package_count, null: false
      t.datetime :created_at, null: false
      t.datetime :last_used_at, null: false
      t.index :content_hash, unique: true
      t.index :chunk_ids, using: :gin
      t.check_constraint "cardinality(chunk_ids) = 64", name: "package_sets_chunk_ids_by_bucket"
    end

    create_table :chunk_matches, primary_key: %i[package_chunk_id ecosystem advisory_id package architecture] do |t|
      t.references :package_chunk, null: false, index: false, foreign_key: { on_delete: :cascade }
      t.string :ecosystem, limit: 64, null: false
      t.references :advisory, null: false, index: true, foreign_key: true
      t.string :package, limit: 128, null: false
      t.string :architecture, limit: 32, null: false
      t.string :source, limit: 128, null: false
      t.string :installed_version, limit: 256, null: false
      t.string :fixed_version, limit: 256
    end

    create_table :chunk_evaluations, primary_key: %i[package_chunk_id ecosystem] do |t|
      t.references :package_chunk, null: false, index: false, foreign_key: { on_delete: :cascade }
      t.string :ecosystem, limit: 64, null: false
      t.jsonb :not_evaluated, null: false, default: []
      t.bigint :advisory_import_id, null: false
      t.datetime :evaluated_at, null: false
      t.index %i[advisory_import_id ecosystem]
    end

    add_column :host_package_sets, :package_set_id, :bigint # NULL: unsupported, or never readable
    add_column :package_snapshots, :package_set_id, :bigint # NULL: unsupported or unreadable

    add_column :vulnerability_findings, :last_source, :string, limit: 128
    add_column :vulnerability_findings, :last_installed_version, :string, limit: 256
    add_column :vulnerability_findings, :last_fixed_version, :string, limit: 256
    add_column :vulnerability_findings, :last_ecosystem, :string, limit: 64
    add_column :host_vulnerability_evaluations, :package_set_id, :bigint
    add_column :advisory_imports, :changed_packages, :jsonb
  end
end
