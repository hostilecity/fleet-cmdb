# Operator second factor (P3-S09, DEC-06): one TOTP authenticator per operator, its recovery codes, and the per-session
# state of the step-up check and of setting one up.
class CreateSecondFactors < ActiveRecord::Migration[8.1]
  def change
    create_table :second_factors do |t|
      t.references :operator, null: false, foreign_key: true, index: { unique: true }
      t.text :secret, null: false # Active Record encryption: ciphertext only (threat model C13)
      t.bigint :last_used_step # the newest 30-second step accepted, so a code works once
      t.integer :failed_attempts, null: false, default: 0
      t.datetime :failures_started_at
      t.datetime :locked_until
      t.datetime :enrolled_at, null: false
      t.datetime :last_accepted_at
      t.timestamps
    end

    create_table :second_factor_recovery_codes do |t|
      t.references :second_factor, null: false, foreign_key: { on_delete: :cascade }, index: false
      t.string :code_digest, limit: 64, null: false # HMAC-SHA256, keyed from FLEET_ENCRYPTION_KEY
      t.datetime :used_at
      t.datetime :created_at, null: false
      t.index %i[second_factor_id code_digest], unique: true, name: "index_second_factor_recovery_codes_on_digest"
    end

    change_table :operator_sessions, bulk: true do |t|
      t.datetime :google_authenticated_at # the session's sign-in, or a later fresh Google sign-in
      t.datetime :second_factor_passed_at # the step-up window starts here
      t.text :pending_second_factor_secret # a key shown for setting up, encrypted, until checked or replaced
      t.datetime :second_factor_replacement_approved_at # moving to a new phone: when its own code was accepted
    end
  end
end
