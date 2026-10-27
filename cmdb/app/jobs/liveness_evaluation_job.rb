# Evaluates host liveness (FR-1.4, P1-S09). Scheduled every minute in config/recurring.yml.
class LivenessEvaluationJob < ApplicationJob
  queue_as :default

  def perform
    Liveness.evaluate!
  end
end
