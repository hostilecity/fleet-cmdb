# Resumes the triage runs whose work died with its worker (reviews of #277). Solid Queue fails the job of a worker that
# was killed (a deploy's restart, the OOM killer) without a retry, so its after_discard never runs and the run would
# stay queued or running for good, showing "No progress" with nothing to press.
#
# Every 10 minutes: the live Solid Queue jobs are read first (not finished and not failed), then the triage runs
# unfinished and untouched for STALE_AFTER. A job live at the first read cannot leave a dead run behind without
# touching the run, so a run that looks dead is dead; each is re-checked under its row lock (state and updated_at as
# read) before anything is done to it. A run is alive while it has a live fan-out job (EvaluationRunJob, a retry
# pending included) or, once running, a live batch job.
#
# A dead run is resumed by queueing its fan-out again: for a queued run that prepares it again (safe from any point,
# EvaluationRun::Triage#prepare!); for a running run it queues the remaining batches again (each is counted once) and
# finishes a run split into none. A running run with no batches left (each was counted, but the worker died before
# the run was) is finished, not resumed. Only resumes with no progress since the last one count (scope "resumes", with the
# state and batches done at the last one in "resume_progress"; preparation is not progress, since a resume prepares
# again from the start); after EvaluationRun::Triage::RESUMES of them in a row the run is
# failed (EvaluationRun#fail_locked!), which shows it on Data sources with "Re-triage again", whose retry carries on
# from its batches (EvaluationRun::Triage.retry!). A run that failed by raising every retry is never resumed, so one
# bad advisory or host cannot stop later runs. Advisory re-matching runs share the gap (#278).
class TriageRunWatchJob < ApplicationJob
  queue_as :default

  STALE_AFTER = 10.minutes
  JOBS = %w[EvaluationRunJob EvaluationBatchJob].freeze

  # Returns { "resumed" => [run ids], "failed" => [run ids], "finished" => [run ids] }.
  def perform(now: Time.current)
    live = live_arguments
    dead = stale_runs(now).reject do |run|
      live["EvaluationRunJob"].include?(run.id) || (run.state == "running" && run.batches.pluck(:id).intersect?(live["EvaluationBatchJob"].to_a))
    end
    dead.each_with_object({ "resumed" => [], "failed" => [], "finished" => [] }) do |run, done|
      outcome = revive(run)
      done[outcome] << run.id if outcome
    end
  end

  private

  def stale_runs(now) = EvaluationRun.where(kind: "triage", state: EvaluationRun::UNFINISHED).where(updated_at: ...now - STALE_AFTER).to_a

  # Under the run's row lock, if it is as it was read: resumes it, or fails it after RESUMES resumes with no progress.
  def revive(run)
    EvaluationRun.transaction do
      locked = EvaluationRun.lock.find_by(id: run.id)
      next nil unless locked && locked.state == run.state && locked.updated_at == run.updated_at

      if locked.state == "running" && !locked.batches.exists?
        locked.finish!
        locked.save!
        next "finished"
      end

      progress = [ locked.state, locked.batches_done ]
      resumes = locked.scope["resume_progress"] == progress ? locked.scope["resumes"].to_i : 0
      if resumes >= EvaluationRun::Triage::RESUMES
        Rails.logger.error("[triage] run #{run.id} died with its job #{resumes + 1} times with no progress: failed")
        locked.fail_locked!
        next "failed"
      end

      Rails.logger.warn("[triage] run #{run.id} has no live job (its worker was killed?): resumed (#{resumes + 1} of #{EvaluationRun::Triage::RESUMES})")
      locked.update!(scope: locked.scope.merge("resumes" => resumes + 1, "resume_progress" => progress))
      ActiveRecord.after_all_transactions_commit { EvaluationRunJob.perform_later(run.id) }
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
