# Signed agent releases imported into the server (P1-RELEASES, ADR 0018). The binary itself lives on disk
# (FLEET_RELEASES_DIR); the row keeps the exact signed manifest and signature bytes, so what is served is what
# was verified. Releases are immutable, and never deleted while a host runs them (agent_releases_guard; a
# rollout's reference arrives with P1-UPDATES).
class CreateAgentReleases < ActiveRecord::Migration[8.1]
  def change
    create_table :agent_releases do |t|
      t.string :version, null: false, limit: 64
      t.string :target, null: false, limit: 64
      t.string :sha256, null: false, limit: 64
      t.bigint :size, null: false
      t.binary :manifest, null: false
      t.binary :signature, null: false
      t.text :trusted_comment, null: false
      # Which configured release key verified it: minisign's key id, and "current" or "next" at import.
      t.string :key_id, null: false, limit: 16
      t.string :key_role, null: false, limit: 16
      t.string :source, null: false, limit: 16
      t.references :imported_by, null: false, foreign_key: { to_table: :operators }, index: false
      t.datetime :imported_at, null: false
      t.timestamps
    end
    add_index :agent_releases, :version, unique: true
    add_check_constraint :agent_releases, "size BETWEEN 1 AND 67108864", name: "agent_releases_size_valid"
    add_check_constraint :agent_releases, "sha256 ~ '^[0-9a-f]{64}$'", name: "agent_releases_sha256_valid"
    add_check_constraint :agent_releases, "key_role IN ('current', 'next')", name: "agent_releases_key_role_valid"
    add_check_constraint :agent_releases, "source IN ('github', 'upload')", name: "agent_releases_source_valid"

    # Imports from GitHub run as a background job; this row is how the operator sees how it went.
    create_table :agent_release_imports do |t|
      t.string :version, null: false, limit: 64
      t.string :state, null: false, default: "queued", limit: 16
      t.text :reason
      t.references :operator, null: false, foreign_key: true, index: false
      t.references :agent_release, foreign_key: true, index: false
      t.string :request_id, limit: 255
      t.datetime :finished_at
      t.timestamps
    end
    add_index :agent_release_imports, :created_at
    # One import of a version at a time.
    add_index :agent_release_imports, :version, unique: true, where: "state IN ('queued', 'running')",
                                                name: "index_agent_release_imports_one_in_flight"
    add_check_constraint :agent_release_imports, "state IN ('queued', 'running', 'imported', 'refused', 'failed')",
                         name: "agent_release_imports_state_valid"
    add_check_constraint :agent_release_imports, "(state IN ('queued', 'running')) = (finished_at IS NULL)",
                         name: "agent_release_imports_finished_at_matches_state"

    create_function :agent_releases_guard
    create_trigger :agent_releases_immutable, on: :agent_releases
    create_trigger :agent_releases_no_truncate, on: :agent_releases
  end
end
