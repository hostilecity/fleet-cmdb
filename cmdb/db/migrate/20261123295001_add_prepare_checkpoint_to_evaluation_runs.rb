# Where a fleet-wide run's preparation got to (#295, EvaluationRun::Checkpoint): the step it reached and, in a step
# that works through ids, the last id it handled, with a digest of the kind's step list it was written under
# (prepare_plan), so a run whose steps changed between attempts (a step added before the one stored) prepares again
# from the start. A resume, or a retry of a run never split, carries on from it, and EvaluationRunWatchJob counts a
# move of it as progress. Nullable columns on a small table (runs are kept 30 days), so adding them rewrites nothing.
#
# triage_run_claims holds the triage_signal_changes rows a triage run claimed (review of #308: in a table, not in the
# run's scope, which Data sources reads on every refresh of its progress line and the watch rewrites on every
# resume). It goes with its run, and once the run has released them.
class AddPrepareCheckpointToEvaluationRuns < ActiveRecord::Migration[8.1]
  def change
    add_column :evaluation_runs, :prepare_step, :string, limit: 80
    add_column :evaluation_runs, :prepare_cursor, :bigint
    add_column :evaluation_runs, :prepare_plan, :string, limit: 16

    create_table :triage_run_claims, primary_key: %i[evaluation_run_id triage_signal_change_id] do |t|
      t.bigint :evaluation_run_id, null: false
      t.bigint :triage_signal_change_id, null: false
    end
    add_foreign_key :triage_run_claims, :evaluation_runs, on_delete: :cascade
  end
end
