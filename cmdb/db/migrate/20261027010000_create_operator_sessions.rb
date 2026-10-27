# Server-side, revocable operator sessions (P1-S01, NFR-1). The session cookie carries only a random token;
# this table holds its digest, so signing out revokes the session even if a copy of the cookie survives.
class CreateOperatorSessions < ActiveRecord::Migration[8.1]
  def change
    create_table :operator_sessions do |t|
      t.references :operator, null: false, foreign_key: true
      t.string :token_digest, null: false, limit: 64
      t.datetime :last_seen_at, null: false
      t.datetime :revoked_at
      t.timestamps
    end
    add_index :operator_sessions, :token_digest, unique: true
  end
end
