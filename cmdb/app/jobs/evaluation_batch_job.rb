# Evaluates one batch of a fleet-wide EvaluationRun (#197): its range of hosts, in short transactions that lock hosts
# in id order. Retries follow ApplicationJob; a retried batch evaluates again (idempotent) and is counted once. A batch
# whose run finished or was superseded no longer exists, and its job does nothing.
class EvaluationBatchJob < ApplicationJob
  queue_as :evaluation

  def perform(batch_id)
    batch = EvaluationBatch.includes(:evaluation_run).find_by(id: batch_id)
    return unless batch&.evaluation_run&.state == "running"

    changed = batch.evaluation_run.work.call(batch.host_range)
    EvaluationRun.batch_done!(batch, changed)
  end
end
