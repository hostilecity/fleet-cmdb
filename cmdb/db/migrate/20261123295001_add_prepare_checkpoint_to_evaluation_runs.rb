# Where a fleet-wide run's preparation got to (#295, EvaluationRun::Checkpoint): the step it reached and, in a step
# that works through ids, the last id it handled. A resume, or a retry of a run never split, carries on from it, and
# EvaluationRunWatchJob counts a move of it as progress. Two nullable columns on a small table (runs are kept 30
# days), so adding them rewrites nothing.
class AddPrepareCheckpointToEvaluationRuns < ActiveRecord::Migration[8.1]
  def change
    add_column :evaluation_runs, :prepare_step, :string, limit: 80
    add_column :evaluation_runs, :prepare_cursor, :bigint
  end
end
