# CIS-aligned rules (P2-S04, FR-2.2, DEC-12). A rule is its stable key and enabled flag; each definition is an
# immutable version, so results can name the version that produced them and history is never rewritten.
class CreateCisRules < ActiveRecord::Migration[8.1]
  def change
    create_table :cis_rules do |t|
      t.string :key, limit: 64, null: false, index: { unique: true }
      t.boolean :enabled, null: false, default: true
      t.bigint :current_version_id
      t.timestamps
    end

    create_table :cis_rule_versions do |t|
      t.references :cis_rule, null: false, foreign_key: true, index: false
      t.integer :version, null: false
      t.string :reference, limit: 128, null: false
      t.string :title, limit: 200, null: false
      t.string :severity, limit: 16, null: false
      t.jsonb :applies_to, null: false
      t.string :fact, limit: 220, null: false
      t.jsonb :condition, null: false
      t.text :remediation, null: false
      t.string :content_hash, limit: 64, null: false
      t.datetime :created_at, null: false
      t.index [ :cis_rule_id, :version ], unique: true
      t.index :fact
      t.check_constraint "severity IN ('low', 'medium', 'high', 'critical')", name: "cis_rule_versions_severity"
      t.check_constraint "version > 0", name: "cis_rule_versions_version_positive"
    end

    add_foreign_key :cis_rules, :cis_rule_versions, column: :current_version_id
    add_index :cis_rules, :current_version_id, unique: true
  end
end
