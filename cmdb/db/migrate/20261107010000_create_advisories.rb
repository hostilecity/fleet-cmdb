# Vulnerability advisories (P2-VULNS, FR-2.4, DEC-11): OSV records for the fleet profile's ecosystems, the
# packages and version ranges each one affects, and every import, which is how the dashboard knows how fresh
# the data is (P2-S13).
class CreateAdvisories < ActiveRecord::Migration[8.1]
  def change
    create_table :advisories do |t|
      t.string :advisory_id, null: false, limit: 128 # the OSV id, for example DSA-5800-1 or DEBIAN-CVE-2026-0001
      t.string :source, null: false, limit: 256      # where the version stored came from (feed host and path, or file name)
      t.string :summary, limit: 512
      t.string :aliases, array: true, null: false, default: []
      t.string :severity, null: false, limit: 16
      t.string :severity_raw, limit: 512             # what the normalised severity was derived from
      t.string :reference_url, limit: 2048           # http or https only
      t.datetime :published_at
      t.datetime :modified_at, null: false
      t.datetime :withdrawn_at
      t.string :withdrawn_reason, limit: 16          # withdrawn: the record says so; absent: missing from a full import
      t.timestamps
      t.index :advisory_id, unique: true
      t.check_constraint "severity IN ('critical', 'high', 'medium', 'low', 'unknown')", name: "advisories_severity_valid"
      t.check_constraint "(withdrawn_at IS NULL) = (withdrawn_reason IS NULL) AND withdrawn_reason IN ('withdrawn', 'absent')",
                         name: "advisories_withdrawn_reason_valid"
    end

    # One row per advisory, ecosystem, and source package. ranges is [[{"introduced" => "0"}, {"fixed" => "1.2-3"}], ...]:
    # each OSV ECOSYSTEM range's events, as published.
    create_table :advisory_packages do |t|
      t.references :advisory, null: false, foreign_key: { on_delete: :cascade }, index: false
      t.string :ecosystem, null: false, limit: 64
      t.string :package, null: false, limit: 128
      t.jsonb :ranges, null: false
      t.string :fixed_version, limit: 256 # the first fixed version, for display
      t.index [ :advisory_id, :ecosystem, :package ], unique: true, name: "index_advisory_packages_unique"
      t.index [ :ecosystem, :package ] # matching looks advisories up by the host's ecosystem and source package
    end

    create_table :advisory_imports do |t|
      t.references :operator, foreign_key: true # nil for the scheduled refresh and rake tasks (the system actor)
      t.string :origin, null: false, limit: 8     # feed or file
      t.string :source, null: false, limit: 256
      t.boolean :full, null: false, default: false # the complete data set for its ecosystems (counts for freshness)
      t.string :state, null: false, limit: 16
      t.string :ecosystems, array: true, null: false, default: []
      t.jsonb :counts, null: false, default: {}
      t.jsonb :problems, null: false, default: [] # malformed records, at most Advisories::Import::PROBLEM_LIMIT
      t.string :reason, limit: 512
      t.string :etag, limit: 256          # the feed's validators, for the next conditional request
      t.string :last_modified, limit: 64
      t.datetime :started_at, null: false
      t.datetime :finished_at, null: false
      t.index :finished_at
      t.check_constraint "state IN ('succeeded', 'failed')", name: "advisory_imports_state_valid"
      t.check_constraint "origin IN ('feed', 'file')", name: "advisory_imports_origin_valid"
    end
  end
end
