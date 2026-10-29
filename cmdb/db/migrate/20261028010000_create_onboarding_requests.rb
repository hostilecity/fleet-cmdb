# Onboarding requests (P1-ONBOARD, DEC-17, FR-S.1): an installer asks to join, an operator approves or rejects
# in the dashboard, and the installer collects its credential once. Kept apart from hosts: a request is not a
# host, and nothing in the hosts table exists until the credential is collected.
class CreateOnboardingRequests < ActiveRecord::Migration[8.1]
  def change
    create_table :onboarding_requests do |t|
      # Secret known only to the installer; SHA-256 digest only.
      t.string :device_code_digest, null: false, limit: 64
      # Shown in the terminal and on the approval page so the operator can match them. It identifies a
      # request and grants nothing by itself (approval needs a signed-in operator), so it is stored as is.
      t.string :user_code, null: false, limit: 9
      t.string :state, null: false, default: "open"

      # What the VM reported, shown to the operator. Agent-supplied: normalised before storage, escaped on display.
      t.string :hostname, limit: 253
      t.string :machine_id, limit: 32
      t.jsonb :os
      t.string :agent_version, null: false, limit: 64
      t.string :client_ip, null: false, limit: 45

      # The operator's decision. host_attributes are the fields entered on the approval page; host_id is the
      # host being re-enrolled (set at approval) or the host created at collection.
      t.references :decided_by, foreign_key: { to_table: :operators }, index: false
      t.datetime :decided_at
      t.jsonb :host_attributes
      t.boolean :reenroll, null: false, default: false
      t.references :host, foreign_key: true, index: true

      t.datetime :expires_at, null: false
      t.datetime :last_polled_at
      t.datetime :collected_at
      t.timestamps
    end
    add_index :onboarding_requests, :device_code_digest, unique: true
    # A user code is reused only once no open request holds it.
    add_index :onboarding_requests, :user_code, unique: true, where: "state = 'open'", name: "index_onboarding_requests_open_user_code"
    add_index :onboarding_requests, [ :state, :expires_at ]
    add_index :onboarding_requests, [ :client_ip, :state ]
    add_check_constraint :onboarding_requests, "state IN ('open', 'approved', 'rejected', 'collected')", name: "onboarding_requests_state_valid"
    add_check_constraint :onboarding_requests, "(state = 'open') = (decided_at IS NULL)", name: "onboarding_requests_decided_at_matches_state"
    add_check_constraint :onboarding_requests, "(state = 'collected') = (collected_at IS NOT NULL)", name: "onboarding_requests_collected_at_matches_state"
    add_check_constraint :onboarding_requests, "NOT reenroll OR host_id IS NOT NULL", name: "onboarding_requests_reenroll_has_host"
  end
end
