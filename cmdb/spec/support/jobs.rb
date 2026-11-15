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

# Fleet-wide evaluation runs (#197), performed as their jobs would be, with every other job left enqueued.
module EvaluationRunHelpers
  EVALUATION_JOBS = [ EvaluationRunJob, EvaluationBatchJob ].freeze

  def run_fleet_evaluation(kind, scope) = perform_evaluation_jobs { EvaluationRun.start!(kind, scope) }

  # With a block, the evaluation jobs it enqueues; without, those enqueued already, and the batches they enqueue.
  def perform_evaluation_jobs(&)
    return perform_enqueued_jobs(only: EVALUATION_JOBS, &) if block_given?

    names = EVALUATION_JOBS.map(&:name)
    perform_enqueued_jobs(only: EVALUATION_JOBS) while enqueued_jobs.any? { |job| names.include?(job["job_class"]) }
  end

  def evaluation_runs = enqueued_jobs.select { |job| job["job_class"] == "EvaluationRunJob" }.map { |job| EvaluationRun.find(job["arguments"].first) }
end

RSpec.configure do |config|
  config.include EvaluationRunHelpers
  # A spec outside the test transaction that changes rules or imports advisories starts runs that would outlive it.
  config.after { EvaluationRun.delete_all unless self.class.use_transactional_tests }

  config.include JobHelpers
end
