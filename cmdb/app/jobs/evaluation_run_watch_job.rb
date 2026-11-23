# Resumes the evaluation runs of every kind whose work died with its worker (reviews of #277 for triage runs, #278 for
# the others). Solid Queue fails the job of a worker that was killed (a deploy's restart past the shutdown timeout, the
# OOM killer) without a retry, so its after_discard never runs and the run would stay queued or running for good,
# showing "No progress" with nothing to press.
#
# Every 10 minutes: the live Solid Queue jobs are read first (not finished and not failed), then the runs unfinished
# and untouched for STALE_AFTER. A job live at the first read cannot leave a dead run behind without touching the run,
# so a run that looks dead is dead; each is re-checked under its row lock (state and updated_at as read) before
# anything is done to it. A run is alive while it has a live fan-out job (EvaluationRunJob, a retry pending included)
# or, once running, a live batch job.
#
# A dead run is resumed from what it recorded, by queueing its fan-out again: a queued run carries on preparing from
# its checkpoint (#295, EvaluationRun::Checkpoint: the step it reached and the last chunk id it handled; each step is
# idempotent, so a page killed part way runs again); a running run queues its remaining batches again (each is counted
# once, and a batch killed part way runs again, idempotently). A running run with no batches left (split into none, and
# killed before it was finished: the last batch's count finishes its run in the same transaction) is finished, not
# resumed. Only resumes with no progress since the last one count (scope "resumes", with [state, batches done,
# preparation step, its cursor] at the last one in "resume_progress"), so a long preparation that moves its checkpoint
# between deploys is resumed every time. After
# EvaluationRun::RESUMES resumes in a row with no progress the run is failed with the reason "stopped"
# (EvaluationRun#fail_locked!), which shows it where it was started with its button, whose retry carries on from its
# batches with a fresh count (EvaluationRun.retry!). A run that failed by
# raising every retry is never resumed, so one bad advisory, rule or host cannot stop later runs. Each resume is one
# transaction, and its job is queued after it commits: a watch killed part way leaves each run resumed or as it was.
class EvaluationRunWatchJob < ApplicationJob
  queue_as :default

  STALE_AFTER = 10.minutes

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

  def stale_runs(now) = EvaluationRun.unfinished.where(updated_at: ...now - STALE_AFTER).order(:id).to_a

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

      progress = [ locked.state, locked.batches_done, locked.prepare_step, locked.prepare_cursor ]
      resumes = locked.scope["resume_progress"] == progress ? locked.scope["resumes"].to_i : 0
      if resumes >= EvaluationRun::RESUMES
        Rails.logger.error("[evaluation] #{run.kind} run #{run.id} died with its job #{resumes + 1} times with no progress: failed")
        locked.fail_locked!(failure: "stopped")
        next "failed"
      end

      Rails.logger.warn("[evaluation] #{run.kind} run #{run.id} has no live job (its worker was killed?): resumed (#{resumes + 1} of #{EvaluationRun::RESUMES})")
      locked.update!(scope: locked.scope.merge("resumes" => resumes + 1, "resume_progress" => progress))
      ActiveRecord.after_all_transactions_commit { EvaluationRunJob.perform_later(run.id) }
      "resumed"
    end
  end

  def live_arguments = EvaluationRun.live_jobs
end
