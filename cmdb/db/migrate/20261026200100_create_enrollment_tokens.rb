# Single-use, expiring enrollment tokens (P1-API-AUTH, P1-S05, DEC-04). Only a SHA-256 digest is stored.
class CreateEnrollmentTokens < ActiveRecord::Migration[8.1]
  def change
    create_table :enrollment_tokens do |t|
      t.references :host, null: false, foreign_key: true
      t.string :token_digest, null: false, limit: 64
      t.datetime :expires_at, null: false
      t.datetime :redeemed_at
      t.timestamps
    end

    add_index :enrollment_tokens, :token_digest, unique: true
  end
end
