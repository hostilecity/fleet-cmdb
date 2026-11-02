# What the dashboard banner, the failed-jobs page, and /health know about background jobs (NFR-4, P1-O02).
#
# Solid Queue keeps a failed execution once a job has used up its retries (ApplicationJob), until someone
# discards it. "Failing" means a job failed in the last RECENT window, so one old failure that was dealt with
# does not hold /health red for ever; every failed job stays on the failed-jobs page.
#
# Liveness: the recurring liveness evaluation (FR-1.4) runs every minute, so a recent finished run shows the
# scheduler, a worker, and the queue database all working. It is read from the queue's own job rows
# (finished jobs are kept a day by clear_solid_queue_finished_jobs in config/recurring.yml).
module JobHealth
  RECENT = 24.hours
  LIVENESS_MAX_AGE = 5.minutes
  LIVENESS_JOB = LivenessEvaluationJob.name
  LIST_LIMIT = 100

  Failure = Data.define(:id, :job_class, :queue, :failed_at, :error_class, :error_message)

  module_function

  def failing_scope(now: Time.current) = SolidQueue::FailedExecution.where(created_at: (now - RECENT)..)

  # Failed jobs in the last RECENT window.
  def failing_count(now: Time.current) = failing_scope(now:).count

  def failing?(now: Time.current) = failing_scope(now:).exists?

  # The recurring liveness job finished within LIVENESS_MAX_AGE.
  def liveness_recent?(now: Time.current)
    finished = SolidQueue::Job.where(class_name: LIVENESS_JOB).maximum(:finished_at)
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
