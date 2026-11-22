# Resumes the triage runs whose work died with its worker (reviews of #277). Solid Queue fails the job of a worker that
# was killed (a deploy's restart, the OOM killer) without a retry, so its after_discard never runs and the run would
# stay queued or running for good, showing "No progress" with nothing to press.
#
# Every 10 minutes: the live Solid Queue jobs are read first (not finished and not failed), then the triage runs
# unfinished and untouched for STALE_AFTER. A job live at the first read cannot leave a dead run behind without
# touching the run, so a run that looks dead is dead; each is re-checked under its row lock (state and updated_at as
# read) before anything is done to it. A dead run is resumed: a queued run's fan-out is queued again (its preparation
# is safe to run again from any point, EvaluationRun::Triage#prepare!), a running run's remaining batches are queued
# again (each is counted once). After EvaluationRun::Triage::RESUMES resumes it is failed instead, which shows it on
# Data sources with "Re-triage again". A run that failed by raising every retry is never resumed, so one bad
# advisory or host cannot stop later runs. Advisory re-matching runs share the gap (#278).
class TriageRunWatchJob < ApplicationJob
  queue_as :default

  STALE_AFTER = 10.minutes
  JOBS = %w[EvaluationRunJob EvaluationBatchJob].freeze

  # Returns { "resumed" => [run ids], "failed" => [run ids] }.
  def perform(now: Time.current)
    live = live_arguments
    runs = EvaluationRun.where(kind: "triage", state: EvaluationRun::UNFINISHED).where(updated_at: ...now - STALE_AFTER).to_a
    dead = runs.reject do |run|
      run.state == "queued" ? live["EvaluationRunJob"].include?(run.id) : run.batches.pluck(:id).intersect?(live["EvaluationBatchJob"].to_a)
    end
    dead.each_with_object({ "resumed" => [], "failed" => [] }) do |run, done|
      outcome = revive(run)
      done[outcome] << run.id if outcome
    end
  end

  private

  # Under the run's row lock, if it is as it was read: resumes it, or fails it after RESUMES resumes.
  def revive(run)
    EvaluationRun.transaction do
      locked = EvaluationRun.lock.find_by(id: run.id)
      next nil unless locked && locked.state == run.state && locked.updated_at == run.updated_at

      resumes = locked.scope["resumes"].to_i
      if resumes >= EvaluationRun::Triage::RESUMES
        Rails.logger.error("[triage] run #{run.id} died with its job #{resumes + 1} times: failed")
        locked.batches.delete_all # as EvaluationRun.fail! does
        FleetBroadcast.refresh if locked.shown_changed
        locked.update!(state: "failed", finished_at: Time.current)
        next "failed"
      end

      Rails.logger.warn("[triage] run #{run.id} has no live job (its worker was killed?): resumed (#{resumes + 1} of #{EvaluationRun::Triage::RESUMES})")
      locked.update!(scope: locked.scope.merge("resumes" => resumes + 1))
      batch_ids = locked.state == "queued" ? [] : locked.batches.order(:position).pluck(:id)
      ActiveRecord.after_all_transactions_commit do
        locked.state == "queued" ? EvaluationRunJob.perform_later(run.id) : ActiveJob.perform_all_later(batch_ids.map { |id| EvaluationBatchJob.new(id) })
      end
      "resumed"
    end
  end

  # { job class => Set of the first argument (a run or batch id) of its live jobs }.
  def live_arguments
    jobs = SolidQueue::Job.where(class_name: JOBS, finished_at: nil).where.missing(:failed_execution).pluck(:class_name, :arguments)
    jobs.each_with_object(Hash.new { |h, k| h[k] = Set.new }) do |(name, arguments), live|
      live[name] << Array(arguments.is_a?(Hash) ? arguments["arguments"] : nil).first
    end
  end
end
