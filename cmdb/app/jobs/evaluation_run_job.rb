# Splits a fleet-wide EvaluationRun into batches and enqueues them (#197). On the evaluation queue, with its own
# workers (config/queue.yml), so liveness, leases, and broadcasts never wait behind fleet-wide work.
class EvaluationRunJob < ApplicationJob
  queue_as :evaluation

  # After the last retry the run is failed, so its page stops showing progress (review of #204).
  after_discard { |job, _error| EvaluationRun.fail!(job.arguments.first) }

  def perform(run_id) = EvaluationRun.find_by(id: run_id)&.fan_out!
end
