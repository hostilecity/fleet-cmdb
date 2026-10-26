# Per-host agent credentials (P1-API-AUTH, P1-S04, FR-S.1). Only a SHA-256 digest of the secret is stored;
# the key id is not secret and is used for lookup. At most one active credential per host.
class CreateAgentCredentials < ActiveRecord::Migration[8.1]
  def change
    create_table :agent_credentials do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.string :key_id, null: false, limit: 64
      t.string :secret_digest, null: false, limit: 64
      t.string :state, null: false, default: "active"
      # /etc/machine-id reported at enrollment, for clone detection (FR-S.1).
      t.string :machine_id, limit: 32
      t.datetime :revoked_at
      t.datetime :last_used_at
      t.timestamps
    end

    add_index :agent_credentials, :key_id, unique: true
    add_index :agent_credentials, :host_id
    add_index :agent_credentials, :host_id, unique: true, where: "state = 'active'", name: "index_agent_credentials_one_active_per_host"
    add_check_constraint :agent_credentials, "state IN ('active', 'revoked')", name: "agent_credentials_state_valid"
    add_check_constraint :agent_credentials, "(state = 'revoked') = (revoked_at IS NOT NULL)", name: "agent_credentials_revoked_at_matches_state"
  end
end
