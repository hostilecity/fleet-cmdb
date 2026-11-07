# A rules file an operator uploaded and is previewing (P2-D06, owner decision Q13): kept for 15 minutes so "Apply
# import" applies exactly the file that was previewed, then dropped when it is applied, cancelled, or expires
# (RuleImportPreviewPruneJob). Bounded: one per operator (a new upload replaces it) and at most the rule file
# limit of 1 MiB, only for a file that passed every check. The token names it in the preview's URL and the apply
# form, so a stale tab cannot apply a later upload; rules_digest is CisRule.state_digest when it was previewed.
class CreateRuleImportPreviews < ActiveRecord::Migration[8.1]
  def change
    create_table :rule_import_previews do |t|
      t.references :operator, null: false, foreign_key: { on_delete: :cascade }, index: { unique: true }
      t.string :token, null: false, limit: 64
      t.string :filename, null: false, limit: 255
      t.text :body, null: false
      t.string :sha256, null: false, limit: 64
      t.boolean :disable_missing, null: false, default: false
      t.string :rules_digest, null: false, limit: 64
      t.datetime :expires_at, null: false
      t.timestamps
    end
    add_index :rule_import_previews, :token, unique: true
    add_index :rule_import_previews, :expires_at
    add_check_constraint :rule_import_previews, "octet_length(body) <= 1048576", name: "rule_import_previews_body_size"
  end
end
