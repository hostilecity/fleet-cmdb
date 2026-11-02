# What the dashboard banner, the failed-jobs page, and /health know about background jobs (NFR-4, P1-O02).
#
# Solid Queue keeps a failed execution once a job has used up its retries (ApplicationJob), until someone
# discards it. "Failing" means a job failed in the last RECENT window, so one old failure that was dealt with
# does not hold /health red for ever; every failed job stays on the failed-jobs page.
#
# Liveness: the recurring liveness evaluation (FR-1.4) runs every minute, so a recent successful run shows the
# scheduler, a worker, and the queue database all working. It is read from the queue's own job rows (finished jobs
# are kept a day by clear_solid_queue_finished_jobs in config/recurring.yml). An attempt that raised is also marked
# finished when retry_on catches the error and enqueues the next attempt, so a finished row counts only if no later
# row shares its Active Job id: a retried attempt is not a success, and a liveness evaluation that keeps failing
# turns this check red within LIVENESS_MAX_AGE, long before its retries run out and failed_jobs notices.
module JobHealth
  RECENT = 24.hours
  LIVENESS_MAX_AGE = 5.minutes
  LIVENESS_JOB = LivenessEvaluationJob.name
  LIST_LIMIT = 100
  # A job row with no later attempt of the same Active Job (retry_on enqueues the next attempt as a new row).
  NOT_RETRIED = <<~SQL.squish.freeze
    NOT EXISTS (SELECT 1 FROM solid_queue_jobs later
                WHERE later.active_job_id = solid_queue_jobs.active_job_id AND later.id > solid_queue_jobs.id)
  SQL

  Failure = Data.define(:id, :job_class, :queue, :failed_at, :error_class, :error_message)

  module_function

  def failing_scope(now: Time.current) = SolidQueue::FailedExecution.where(created_at: (now - RECENT)..)

  # Failed jobs in the last RECENT window.
  def failing_count(now: Time.current) = failing_scope(now:).count

  def failing?(now: Time.current) = failing_scope(now:).exists?

  # An attempt of the recurring liveness job succeeded (finished and was not retried) within LIVENESS_MAX_AGE.
  def liveness_recent?(now: Time.current)
    finished = SolidQueue::Job.where(class_name: LIVENESS_JOB).where.not(finished_at: nil)
                              .where(NOT_RETRIED)
                              .maximum(:finished_at)
    !finished.nil? && finished >= now - LIVENESS_MAX_AGE
  end

  # The newest failures, for the failed-jobs page. Arguments are not shown: they can carry ids and tokens.
  def failures(limit: LIST_LIMIT)
    SolidQueue::FailedExecution.includes(:job).order(created_at: :desc, id: :desc).limit(limit).map do |execution|
      error = execution.error.is_a?(Hash) ? execution.error : {}
      Failure.new(id: execution.id, job_class: execution.job.class_name, queue: execution.job.queue_name,
                  failed_at: execution.created_at, error_class: error["exception_class"].to_s, error_message: error["message"].to_s)
    end
  end

  def total_failed = SolidQueue::FailedExecution.count
end
