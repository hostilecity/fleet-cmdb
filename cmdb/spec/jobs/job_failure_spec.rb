require "rails_helper"

# Background job failure policy and visibility (NFR-4, P1-O02), run through the real Solid Queue tables.
RSpec.describe "Background job failures" do
  let(:failing_job) do
    stub_const("AlwaysFailingJob", Class.new(ApplicationJob) do
      self.queue_adapter = :solid_queue
      queue_as :default

      def perform = raise(ArgumentError, "the <b>disk</b> is full")
    end)
  end

  # Moves due scheduled jobs to ready, claims what is ready, and runs it, as a Solid Queue worker would.
  def work_once
    SolidQueue::ScheduledExecution.dispatch_next_batch(100)
    SolidQueue::ReadyExecution.claim("*", 10, nil).each(&:perform)
  end

  def scheduled_in
    SolidQueue::Job.order(:id).last.scheduled_at - Time.current
  end

  it "retries a failing job with a growing delay, then lists it as failed" do
    failing_job.perform_later
    waits = []

    (ApplicationJob::ATTEMPTS - 1).times do
      work_once
      expect(SolidQueue::FailedExecution.count).to eq(0) # still being retried
      waits << scheduled_in
      travel_to(SolidQueue::Job.order(:id).last.scheduled_at + 1.second)
    end
    expect { work_once }.to raise_error(ArgumentError) # the last attempt: recorded as failed, then raised to the worker pool

    expect(waits).to eq(waits.sort)
    expect(waits.first).to be >= 2
    expect(waits.last).to be > 60
    expect(SolidQueue::FailedExecution.count).to eq(1)
    failure = JobHealth.failures.sole
    expect(failure.job_class).to eq("AlwaysFailingJob")
    expect(failure.error_class).to eq("ArgumentError")
    expect(failure.error_message).to eq("the <b>disk</b> is full")
    expect(JobHealth).to be_failing
    expect(JobHealth.failing_count).to eq(1)
  ensure
    travel_back
  end

  it "does not report a job that fails once and then succeeds" do
    attempts = 0
    stub_const("FlakyJob", Class.new(ApplicationJob) do
      self.queue_adapter = :solid_queue
      define_method(:perform) { (attempts += 1) < 2 ? raise("once") : :done }
    end)
    FlakyJob.perform_later

    work_once
    travel_to(10.seconds.from_now) { work_once }

    expect(attempts).to eq(2)
    expect(JobHealth).not_to be_failing
  ensure
    travel_back
  end

  it "does not count a liveness evaluation that raised and was retried as a run, only one that succeeded (review of #83)" do
    allow(LivenessEvaluationJob).to receive(:queue_adapter).and_return(ActiveJob::QueueAdapters::SolidQueueAdapter.new)
    calls = 0
    allow(Liveness).to receive(:evaluate!) { (calls += 1) < 3 ? raise(ActiveRecord::Deadlocked, "deadlock") : 0 }
    LivenessEvaluationJob.perform_later

    work_once # attempt 1 raises; retry_on marks it finished and enqueues attempt 2
    expect(SolidQueue::Job.where(class_name: "LivenessEvaluationJob").where.not(finished_at: nil).count).to eq(1)
    expect(JobHealth).not_to be_liveness_recent

    travel_to(SolidQueue::Job.order(:id).last.scheduled_at + 1.second) { work_once } # attempt 2 raises too
    travel_to(SolidQueue::Job.order(:id).last.scheduled_at + 1.second) do
      expect(JobHealth).not_to be_liveness_recent
      work_once # attempt 3 succeeds
      expect(calls).to eq(3)
      expect(JobHealth).to be_liveness_recent
    end
    expect(SolidQueue::FailedExecution.count).to eq(0)
  ensure
    travel_back
  end

  it "leaves AgentReleaseImportJob's own retry policy in place" do
    handlers = AgentReleaseImportJob.rescue_handlers.map(&:first)
    expect(handlers).to include("Releases::Github::Unavailable", "StandardError")
    expect(handlers.index("Releases::Github::Unavailable")).to be > handlers.index("StandardError") # later handlers are tried first
  end

  describe JobHealth do
    it "counts only failures inside the window, and lists the newest first with the total" do
      old = failed_job(class_name: "OldJob", at: 3.days.ago)
      recent = failed_job(class_name: "RecentJob", at: 1.hour.ago)

      expect(described_class.failing_count).to eq(1)
      expect(described_class.total_failed).to eq(2)
      expect(described_class.failures.map(&:id)).to eq([ recent.id, old.id ])
    end

    it "reads a failure whose stored error is not the usual hash" do
      job = SolidQueue::Job.create!(queue_name: "default", class_name: "OddJob")
      SolidQueue::FailedExecution.create!(job:, error: nil)

      expect(described_class.failures.sole).to have_attributes(job_class: "OddJob", error_class: "", error_message: "")
    end
  end
end
