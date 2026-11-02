# Helpers for specs that look at background job state (P1-O02). Solid Queue's tables live in the test queue
# database, as in production.
module JobHelpers
  # The recurring liveness job finished at `at`, as /health expects it to every minute.
  def liveness_job_ran(at: Time.current)
    SolidQueue::Job.create!(queue_name: "default", class_name: LivenessEvaluationJob.name, finished_at: at)
  end

  # A job that failed all its retries `at`, with the error Solid Queue stores.
  def failed_job(class_name: "RetentionPruneJob", queue: "default", at: Time.current, error_class: "RuntimeError", message: "boom")
    job = SolidQueue::Job.create!(queue_name: queue, class_name:)
    SolidQueue::FailedExecution.create!(job:, created_at: at, error: { "exception_class" => error_class, "message" => message, "backtrace" => [] })
  end
end

RSpec.configure do |config|
  config.include JobHelpers
end
