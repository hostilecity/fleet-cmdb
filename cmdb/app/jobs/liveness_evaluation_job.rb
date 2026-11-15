# Evaluates host liveness (FR-1.4, P1-S09). Scheduled every minute in config/recurring.yml.
class LivenessEvaluationJob < ApplicationJob
  queue_as :realtime # every minute; its own worker, so long jobs never delay it (S-7, config/queue.yml)

  def perform
    Liveness.evaluate!
  end
end
