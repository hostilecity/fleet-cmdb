# CIS-aligned rule results (P2-S06, FR-2.2, DEC-12): the current result of each rule on each host, and a history
# of result changes only, so the dashboard can show a failure appearing and clearing without storing every
# evaluation. Results name the rule version and config snapshot that produced them. A snapshot may be pruned
# (Retention keeps only the newest per host), so its id is cleared rather than blocking the delete.
class CreateCisResults < ActiveRecord::Migration[8.1]
  RESULTS = %w[pass fail not_applicable not_readable not_evaluated].freeze

  def change
    create_table :cis_results do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.references :cis_rule, null: false, foreign_key: true
      t.references :cis_rule_version, foreign_key: true, index: false # null when the rule was not evaluated
      t.references :config_snapshot, foreign_key: { on_delete: :nullify }, index: false
      t.string :result, null: false, limit: 16
      t.jsonb :observed # the value as reported, at most 1 KiB of JSON (CisRules::Evaluator)
      t.string :reason, limit: 512
      t.datetime :evaluated_at, null: false
      t.datetime :changed_at, null: false # when result last changed
      t.check_constraint "result IN (#{RESULTS.map { |r| "'#{r}'" }.join(', ')})", name: "cis_results_result_valid"
    end
    add_index :cis_results, [ :host_id, :cis_rule_id ], unique: true
    add_index :cis_results, :config_snapshot_id

    create_table :cis_result_changes do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.references :cis_rule, null: false, foreign_key: true, index: false
      t.references :cis_rule_version, foreign_key: true, index: false
      t.references :config_snapshot, foreign_key: { on_delete: :nullify }
      t.string :from_result, limit: 16 # null for a host's first result for the rule
      t.string :to_result, null: false, limit: 16
      t.jsonb :observed
      t.string :reason, limit: 512
      t.datetime :occurred_at, null: false
      t.check_constraint "from_result IS NULL OR from_result IN (#{RESULTS.map { |r| "'#{r}'" }.join(', ')})", name: "cis_result_changes_from_valid"
      t.check_constraint "to_result IN (#{RESULTS.map { |r| "'#{r}'" }.join(', ')})", name: "cis_result_changes_to_valid"
      t.check_constraint "from_result IS DISTINCT FROM to_result", name: "cis_result_changes_is_a_change"
    end
    add_index :cis_result_changes, [ :host_id, :occurred_at ]
    add_index :cis_result_changes, [ :cis_rule_id, :occurred_at ]
    add_index :cis_result_changes, :occurred_at
  end
end
