# Fleet-wide CIS evaluation and advisory re-matching, split into batches (#197, P2-S06, P2-S11). A run is one
# trigger (a rule change, an advisory import); its batches are keyset ranges of host ids, each a job of its own.
# A batch row is deleted when its job finishes, so a retried or duplicated job counts once; the run keeps the
# counts the dashboard shows as progress. A run whose fan-out or a batch failed every retry is failed (review of #204).
class CreateEvaluationRuns < ActiveRecord::Migration[8.1]
  def change
    create_table :evaluation_runs do |t|
      t.string :kind, limit: 16, null: false
      t.jsonb :scope, null: false, default: {}
      t.string :state, limit: 16, null: false, default: "queued"
      t.integer :batch_count, null: false, default: 0
      t.integer :batches_done, null: false, default: 0
      t.integer :host_count, null: false, default: 0
      t.integer :hosts_done, null: false, default: 0
      t.boolean :shown_changed, null: false, default: false
      t.references :superseded_by, foreign_key: { to_table: :evaluation_runs, on_delete: :nullify }, index: false
      t.datetime :started_at
      t.datetime :finished_at
      t.timestamps
      t.check_constraint "kind IN ('cis_rules', 'advisories')", name: "evaluation_runs_kind_valid"
      t.check_constraint "state IN ('queued', 'running', 'finished', 'superseded', 'failed')", name: "evaluation_runs_state_valid"
      t.index %i[kind state], where: "state IN ('queued', 'running')", name: "index_evaluation_runs_unfinished"
      t.index :finished_at
    end

    create_table :evaluation_batches do |t|
      t.references :evaluation_run, null: false, foreign_key: { on_delete: :cascade }, index: false
      t.integer :position, null: false
      t.bigint :first_host_id, null: false
      t.bigint :last_host_id, null: false
      t.integer :host_count, null: false
      t.index %i[evaluation_run_id position], unique: true
    end
  end
end
