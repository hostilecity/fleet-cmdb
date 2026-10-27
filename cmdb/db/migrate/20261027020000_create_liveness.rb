# Heartbeats and liveness (P1-HEARTBEAT, FR-1.2, FR-1.4): the agent-reported clock stored apart from
# last_seen_at, typed settings for the liveness thresholds, and the host status history (not the audit log).
class CreateLiveness < ActiveRecord::Migration[8.1]
  def change
    # The agent's own clock from its last heartbeat. Display only; never used for liveness.
    add_column :hosts, :agent_reported_at, :datetime

    create_table :settings do |t|
      t.string :key, null: false, limit: 100
      t.jsonb :value, null: false
      t.timestamps
    end
    add_index :settings, :key, unique: true

    create_table :host_status_events do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.string :from_status
      t.string :to_status, null: false
      t.string :reason, null: false
      t.datetime :occurred_at, null: false
    end
    add_index :host_status_events, [ :host_id, :occurred_at ]
    add_index :host_status_events, :occurred_at
    add_check_constraint :host_status_events, "to_status IN ('online', 'stale', 'offline')", name: "host_status_events_to_status_valid"
    add_check_constraint :host_status_events, "from_status IS NULL OR from_status IN ('online', 'stale', 'offline')", name: "host_status_events_from_status_valid"
    add_check_constraint :host_status_events, "from_status IS DISTINCT FROM to_status", name: "host_status_events_is_a_change"
    add_check_constraint :host_status_events, "reason IN ('heartbeat', 'evaluation')", name: "host_status_events_reason_valid"
  end
end
