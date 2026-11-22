# Fails the triage runs whose work died with its worker (review of #277, re-check B1), then starts a run that repairs
# them. Solid Queue fails the job of a worker that was killed (a deploy's restart, the OOM killer) without a retry, so
# its after_discard never runs and the run would stay queued or running for good, showing "No progress" with nothing to
# press. Every STALE_AFTER: a triage run unfinished and untouched for that long whose fan-out job (queued) or batch jobs
# (running) have no live Solid Queue job (one not finished and not failed) is failed (EvaluationRun.fail!), which shows
# it on Data sources with "Re-triage again"; and one triage run (reason repair) starts at once, which adopts every
# failed run's recorded chunks and advisories (EvaluationRun::Triage#adoptable), re-runs their hosts, and supersedes
# them. Advisory re-matching runs share the gap; they are tracked in their own issue.
class TriageRunWatchJob < ApplicationJob
  queue_as :default

  STALE_AFTER = 10.minutes
  JOBS = %w[EvaluationRunJob EvaluationBatchJob].freeze

  def perform(now: Time.current)
    runs = EvaluationRun.where(kind: "triage", state: EvaluationRun::UNFINISHED).where(updated_at: ...now - STALE_AFTER).to_a
    return [] if runs.empty?

    live = live_arguments
    dead = runs.reject do |run|
      run.state == "queued" ? live["EvaluationRunJob"].include?(run.id) : run.batches.pluck(:id).intersect?(live["EvaluationBatchJob"].to_a)
    end
    dead.each do |run|
      Rails.logger.error("[triage] run #{run.id} has no live job (its worker was killed?): failed, and a repair run started")
      EvaluationRun.fail!(run.id)
    end
    EvaluationRun.start!("triage", { "reason" => "repair" }) if dead.any?
    dead.map(&:id)
  end

  private

  # { job class => Set of the first argument (a run or batch id) of its live jobs }.
  def live_arguments
    jobs = SolidQueue::Job.where(class_name: JOBS, finished_at: nil).where.missing(:failed_execution).pluck(:class_name, :arguments)
    jobs.each_with_object(Hash.new { |h, k| h[k] = Set.new }) do |(name, arguments), live|
      live[name] << Array(arguments.is_a?(Hash) ? arguments["arguments"] : nil).first
    end
  end
end
