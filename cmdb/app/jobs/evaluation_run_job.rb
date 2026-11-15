# Splits a fleet-wide EvaluationRun into batches and enqueues them (#197). On the evaluation queue, with its own
# workers (config/queue.yml), so liveness, leases, and broadcasts never wait behind fleet-wide work.
class EvaluationRunJob < ApplicationJob
  queue_as :evaluation

  def perform(run_id) = EvaluationRun.find_by(id: run_id)&.fan_out!
end
