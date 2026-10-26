# Host records and the FR-1.1 enrollment state machine (P1-HOSTS, P1-S02).
class CreateHosts < ActiveRecord::Migration[8.1]
  def change
    create_table :hosts do |t|
      t.string :name, null: false, limit: 100
      t.string :hostname, null: false, limit: 253
      t.text :description
      t.text :notes
      t.string :tags, array: true, null: false, default: []
      t.string :enrollment_state, null: false, default: "pending"
      t.datetime :first_seen_at
      t.datetime :last_seen_at
      t.string :agent_version, limit: 64
      t.integer :agent_schema_version
      # Written by the liveness job (P1-HEARTBEAT); meaningful for active hosts only.
      t.string :liveness_status
      t.timestamps
    end

    add_index :hosts, :enrollment_state
    add_index :hosts, :liveness_status
    add_index :hosts, :tags, using: :gin
    add_index :hosts, :hostname

    add_check_constraint :hosts, "enrollment_state IN ('pending', 'active', 'revoked', 'retired')",
                         name: "hosts_enrollment_state_valid"
    add_check_constraint :hosts, "liveness_status IS NULL OR liveness_status IN ('online', 'stale', 'offline')",
                         name: "hosts_liveness_status_valid"
  end
end
