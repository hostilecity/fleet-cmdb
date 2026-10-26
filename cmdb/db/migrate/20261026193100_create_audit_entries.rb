# Append-only audit log (P1-HOSTS, P1-S03, FR-S.3). Rows are written only through Audit.record; a
# database trigger rejects UPDATE, DELETE, and TRUNCATE so no code path can rewrite history.
class CreateAuditEntries < ActiveRecord::Migration[8.1]
  def change
    create_table :audit_entries do |t|
      t.string :actor_type, null: false
      t.bigint :actor_id
      t.string :action, null: false
      t.string :target_type
      t.bigint :target_id
      t.jsonb :changeset, null: false, default: {}
      # ActionDispatch::RequestId accepts incoming X-Request-Id values up to 255 characters.
      t.string :request_id, limit: 255
      # Server clock, set by the database, never by the caller.
      t.datetime :occurred_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end

    add_index :audit_entries, :occurred_at
    add_index :audit_entries, [ :target_type, :target_id, :occurred_at ], name: "index_audit_entries_on_target"
    add_index :audit_entries, [ :actor_type, :actor_id, :occurred_at ], name: "index_audit_entries_on_actor"
    add_index :audit_entries, [ :action, :occurred_at ]

    add_check_constraint :audit_entries, "actor_type IN ('operator', 'host', 'system')", name: "audit_entries_actor_type_valid"
    add_check_constraint :audit_entries, "(actor_type = 'system') = (actor_id IS NULL)", name: "audit_entries_actor_id_matches_type"

    create_function :audit_entries_append_only
    create_trigger :audit_entries_no_update_or_delete, on: :audit_entries
    create_trigger :audit_entries_no_truncate, on: :audit_entries
  end
end
