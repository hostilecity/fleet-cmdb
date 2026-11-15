require "rails_helper"

# S-7: the jobs that run every minute, and the live-refresh broadcasts, are on the realtime queue, which a worker of
# its own serves (config/queue.yml), so long jobs on the default queue can never delay them.
RSpec.describe "config/queue.yml" do
  let(:realtime_jobs) do
    [ LivenessEvaluationJob, TaskLeaseJob, TaskExpiryJob, RolloutTimeoutJob, ReportRequestExpiryJob, FleetBroadcastJob, TaskBroadcastJob ]
  end

  def workers(env: "production")
    ActiveSupport::ConfigurationFile.parse(Rails.root.join("config/queue.yml")).deep_symbolize_keys.fetch(env.to_sym).fetch(:workers)
  end

  def job_classes
    Rails.root.glob("app/jobs/*_job.rb").map { |path| path.basename(".rb").to_s.camelize.constantize } - [ ApplicationJob ]
  end

  it "runs a worker that serves only the realtime queue, in every environment, beside one for every queue" do
    %w[development test production].each do |env|
      expect(workers(env:).map { |w| w[:queues] }).to eq([ "realtime", "*" ]), env
      expect(workers(env:).first).to include(threads: 1, processes: 1)
    end
  end

  it "puts every job scheduled every minute on the realtime queue, and the broadcasts" do
    recurring = YAML.load_file(Rails.root.join("config/recurring.yml"))
    every_minute = recurring.values.flat_map(&:values).select { |task| task["schedule"] == "every minute" }
                            .map { |task| task.fetch("class").constantize }.uniq
    expect(every_minute).to contain_exactly(LivenessEvaluationJob, TaskLeaseJob, TaskExpiryJob, RolloutTimeoutJob, ReportRequestExpiryJob)
    expect(recurring.values.flat_map(&:values).pluck("queue").compact).to be_empty # the job class decides its queue

    realtime_jobs.each { |job| expect(job.new.queue_name).to eq("realtime"), job.name }
  end

  it "keeps every other job, the long ones included, off the realtime queue" do
    others = job_classes - realtime_jobs
    expect(others).to include(AdvisoryFeedRefreshJob, DebianTriageRefreshJob, AdvisoryUploadImportJob, VulnerabilityMatchJob,
                              CisEvaluationJob, AgentReleaseImportJob, RetentionPruneJob)
    others.each { |job| expect(job.new.queue_name).to eq("default"), job.name }
  end

  it "runs the every-minute jobs before a backlog of broadcasts on the realtime queue" do
    adapter = ActiveJob::QueueAdapters::SolidQueueAdapter.new
    3.times { adapter.enqueue(FleetBroadcastJob.new([])) }
    adapter.enqueue(TaskBroadcastJob.new)
    adapter.enqueue(TaskLeaseJob.new)
    adapter.enqueue(LivenessEvaluationJob.new)

    order = Array.new(6) { SolidQueue::ReadyExecution.claim([ "realtime" ], 1, nil).sole.job.class_name }
    expect(order.first(2)).to eq(%w[TaskLeaseJob LivenessEvaluationJob])
    expect(order.drop(2)).to all(end_with("BroadcastJob"))
  end

  it "sizes the database pool for every process it configures" do
    pool = ActiveRecord::Base.configurations.configs_for(env_name: "production").map { |c| c.configuration_hash[:max_connections] }.uniq.sole
    expect(pool).to be >= workers.map { |w| w[:threads] }.max + 2 # Solid Queue: threads, polling, heartbeat
    expect(pool).to be >= ProcessSizing.web_threads
    configuration = SolidQueue::Configuration.new(mode: :fork)
    expect(configuration).to be_valid
    expect(configuration.warnings).to be_empty # Solid Queue's own check of the pool against its workers
  end

  # The real workers from config/queue.yml, each in a thread (Solid Queue's async mode) instead of a process, on the
  # test queue database. Committed for real, so the workers' own connections see the jobs.
  describe "a long-running default job" do
    self.use_transactional_tests = false

    let(:adapter) { ActiveJob::QueueAdapters::SolidQueueAdapter.new }
    let(:started) { Queue.new }
    let(:release) { Concurrent::Event.new }
    let(:evaluated) { Queue.new }

    before do
      gate = [ started, release ]
      stub_const("SlowImportJob", Class.new(ApplicationJob) do
        queue_as :default
        define_method(:perform) do
          gate.first << :busy
          gate.last.wait(60)
        end
      end)
      allow(Liveness).to receive(:evaluate!) { evaluated << Time.current }
    end

    after do
      release.set
      @running&.each(&:stop)
      [ SolidQueue::ReadyExecution, SolidQueue::ClaimedExecution, SolidQueue::FailedExecution, SolidQueue::ScheduledExecution,
        SolidQueue::Process, SolidQueue::Job ].each(&:delete_all)
    end

    def start(configuration)
      @running = configuration.configured_processes.map(&:instantiate).each do |worker|
        worker.mode = :async
        worker.start
      end
    end

    # Fills every thread of the worker for every queue with a job that does not end, and queues one more behind them.
    def fill_default_threads(threads)
      (threads + 1).times { adapter.enqueue(SlowImportJob.new) }
      threads.times { Timeout.timeout(15) { started.pop } }
    end

    it "cannot hold up the every-minute jobs: the realtime worker runs them while every default thread is busy" do
      start(SolidQueue::Configuration.new(mode: :async, only_work: true))
      fill_default_threads(ProcessSizing.job_threads)

      adapter.enqueue(LivenessEvaluationJob.new)
      ran_at = Timeout.timeout(15) { evaluated.pop }

      expect(release).not_to be_set
      expect(started).to be_empty # no slow job ended, and the queued one is still waiting
      expect(SolidQueue::ClaimedExecution.joins(:job).where(job: { class_name: "SlowImportJob" }).count).to eq(ProcessSizing.job_threads)
      expect(SolidQueue::ReadyExecution.joins(:job).where(job: { class_name: "SlowImportJob" }).count).to eq(1)
      expect(ran_at).to be_within(15.seconds).of(Time.current)
    end

    it "would starve them with one worker for every queue, as before S-7 (so the example above can fail)" do
      start(SolidQueue::Configuration.new(mode: :async, only_work: true, workers: [ { queues: "*", threads: 3, polling_interval: 1 } ]))
      fill_default_threads(3)

      adapter.enqueue(LivenessEvaluationJob.new)
      sleep 3 # three polling intervals

      expect(evaluated).to be_empty
      release.set
      expect(Timeout.timeout(15) { evaluated.pop }).to be_present # it runs once a thread is free
    end
  end
end
