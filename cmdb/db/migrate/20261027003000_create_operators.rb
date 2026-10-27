# Operators and the sign-in allowlist (P1-ACCESS, P1-S01, FR-S.4, DEC-06). Operators are keyed by their
# Google account (subject id); there are no passwords. Only emails on the allowlist can sign in.
class CreateOperators < ActiveRecord::Migration[8.1]
  def change
    create_table :operators do |t|
      t.string :google_uid, null: false, limit: 255
      t.string :email, null: false, limit: 254
      t.string :name, limit: 255
      t.datetime :last_signed_in_at
      t.timestamps
    end
    add_index :operators, :google_uid, unique: true
    add_index :operators, :email

    create_table :operator_allowlist_entries do |t|
      t.string :email, null: false, limit: 254
      t.timestamps
    end
    add_index :operator_allowlist_entries, :email, unique: true
    add_check_constraint :operator_allowlist_entries, "email = lower(email)", name: "operator_allowlist_entries_email_lowercase"
  end
end
