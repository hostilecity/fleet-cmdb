# Evaluates one batch of a fleet-wide EvaluationRun (#197): its range of hosts, in short transactions that lock hosts
# in id order. Retries follow ApplicationJob; a retried batch evaluates again (idempotent) and is counted once. A batch
# whose run finished or was superseded no longer exists, and one whose run failed is kept for its retry but is not
# running: either way its job does nothing. A batch that fails every retry fails its run. A batch whose worker was
# killed is queued again by EvaluationRunWatchJob (#278).
class EvaluationBatchJob < ApplicationJob
  queue_as :evaluation

  # After the last retry the batch's run is failed, and its other batches do nothing (review of #204).
  after_discard { |job, _error| EvaluationRun.fail!(EvaluationBatch.where(id: job.arguments.first).pick(:evaluation_run_id)) }

  def perform(batch_id)
    batch = EvaluationBatch.includes(:evaluation_run).find_by(id: batch_id)
    return unless batch&.evaluation_run&.state == "running"

    changed = batch.evaluation_run.work.call(batch.host_range)
    EvaluationRun.batch_done!(batch, changed)
  end
end
