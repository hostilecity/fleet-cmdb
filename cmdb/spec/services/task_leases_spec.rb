require "rails_helper"

# P3-S05: the expiry and lease jobs (FR-3.2, AC-3.5 server half, AC-3.8). Every change is a transition audited with
# the system as actor; running the jobs again changes nothing more.
RSpec.describe TaskLeases do
  let(:operator) { create(:operator) }
  let(:host) { task_host(last_seen_at: 1.hour.ago) }

  def task_for(state, type: "refresh_reports", created: Time.current, started: Time.current)
    task = TaskBatches.create!({ "type" => type, "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, operator:, now: created).tasks.sole
    task.claim!(actor: host, lease_expires_at: created + AgentTasks::CLAIM_LEASE, now: created) if %w[claimed running].include?(state)
    task.start!(actor: host, lease_expires_at: started + task.timeout + AgentTasks::RESULT_GRACE, now: started) if state == "running"
    task
  end

  def system_entries(action) = AuditEntry.where(action:, actor_type: "system")

  describe ".expire!" do
    it "expires a queued task at its expiry, and only then (AC-3.8)" do
      task = task_for("queued", created: 2.days.ago)
      fresh = task_for("queued")
      expect(described_class.expire!(now: task.expires_at - 1.second)).to eq(0)
      expect(described_class.expire!).to eq(1)
      expect(task.reload).to have_attributes(state: "expired", finished_at: be_present)
      expect(fresh.reload.state).to eq("queued")
      expect(system_entries(Audit::Actions::TASK_EXPIRED).sole.target_id).to eq(task.id)
      expect(described_class.expire!).to eq(0) # idempotent
      expect(system_entries(Audit::Actions::TASK_EXPIRED).count).to eq(1)
    end

    it "returns a claimed task past its expiry to the queue and expires it, so it never blocks its host (#30 handover)" do
      task = task_for("claimed", created: 2.days.ago)
      task.renew_lease!(lease_expires_at: 1.minute.from_now) # a lease still running does not save it
      described_class.expire!
      expect(task.reload.state).to eq("expired")
      expect(AuditEntry.where(target_type: "Task", target_id: task.id, actor_type: "system").order(:id).pluck(:action))
        .to eq([ Audit::Actions::TASK_REQUEUED, Audit::Actions::TASK_EXPIRED ])
    end

    it "uses the expiry each task was created with, whatever the setting says now" do
      task = task_for("queued", created: 2.hours.ago)
      TaskSettings.update_limits!({ "expiry_hours" => { "refresh_reports" => "1" } }, actor: operator)
      described_class.expire!
      expect(task.reload.state).to eq("queued")
    end

    it "never touches running or finished tasks" do
      running = task_for("running", created: 2.days.ago)
      expect(described_class.expire!).to eq(0)
      expect(running.reload.state).to eq("running")
    end

    it "runs from the recurring job, every minute in every environment that runs jobs" do
      task = task_for("queued", created: 2.days.ago)
      TaskExpiryJob.perform_now
      expect(task.reload.state).to eq("expired")
      recurring = YAML.load_file(Rails.root.join("config/recurring.yml"), aliases: true)
      %w[production development].each do |env|
        expect(recurring.fetch(env)["task_expiry"]).to eq("class" => "TaskExpiryJob", "schedule" => "every minute")
        expect(recurring.fetch(env)["task_leases"]).to eq("class" => "TaskLeaseJob", "schedule" => "every minute")
      end
    end
  end

  describe ".lapse!" do
    it "returns a claim the agent never started to the queue when its lease lapses, and the next poll claims it again" do
      task = task_for("claimed", created: 10.minutes.ago)
      expect(described_class.lapse!).to eq("queued" => 1)
      expect(task.reload).to have_attributes(state: "queued", claimed_at: nil, lease_expires_at: nil)
      expect(system_entries(Audit::Actions::TASK_REQUEUED).sole.target_id).to eq(task.id)
      expect(described_class.lapse!).to eq({})
    end

    it "leaves a claim whose lease is still running" do
      task = task_for("claimed", created: 1.minute.ago)
      expect(described_class.lapse!).to eq({})
      expect(task.reload.state).to eq("claimed")
    end

    it "times out a running task with no result after its deadline and grace when its agent is still heard from (AC-3.5)" do
      task = task_for("running", started: 20.minutes.ago) # refresh_reports: 10 minutes, plus 5 of grace
      host.update_columns(last_seen_at: 1.minute.ago)
      expect(described_class.lapse!(now: task.lease_expires_at - 1.second)).to eq({})
      expect(described_class.lapse!).to eq("timed_out" => 1)
      expect(task.reload).to have_attributes(state: "timed_out", reason: nil, lease_expires_at: nil, result_digest: nil)
      expect(system_entries(Audit::Actions::TASK_TIMED_OUT).sole.changeset).to eq("state" => %w[running timed_out])
    end

    it "counts progress after the deadline as being heard from" do
      task = task_for("running", started: 20.minutes.ago)
      task.update_columns(progress_reported_at: 6.minutes.ago, progress_percent: 90)
      described_class.lapse!
      expect(task.reload.state).to eq("timed_out")
    end

    it "fails a running task with lease_expired when its agent stopped reporting (FR-3.2, threat model L4)" do
      task = task_for("running", started: 20.minutes.ago)
      host.update_columns(last_seen_at: 19.minutes.ago) # last heard before the deadline
      expect(described_class.lapse!).to eq("failed" => 1)
      expect(task.reload).to have_attributes(state: "failed", reason: "lease_expired")
      entry = system_entries(Audit::Actions::TASK_FAILED).sole
      expect(entry.changeset).to eq("state" => %w[running failed], "reason" => "lease_expired")
    end

    it "keeps a result that arrives afterwards as a late result, without changing the state (P3-S04)" do
      task = task_for("running", started: 20.minutes.ago)
      described_class.lapse!
      payload = ApiContract.example("task-result.request", "succeeded")
      Task.transaction { AgentTasks.record_result!(host:, task: task.reload, payload:) }
      expect(task.reload.state).to eq("failed")
      expect(task.late_result.outcome).to eq("succeeded")
    end

    it "runs from the recurring job" do
      task = task_for("claimed", created: 10.minutes.ago)
      TaskLeaseJob.perform_now
      expect(task.reload.state).to eq("queued")
    end

    it "stops after MAX_PER_RUN tasks and leaves the rest for the next run" do
      stub_const("TaskLeases::MAX_PER_RUN", 1)
      first = task_for("claimed", created: 10.minutes.ago)
      other = task_host
      second = create_task(other, operator:)
      second.claim!(actor: other, lease_expires_at: 1.minute.ago)
      expect(described_class.lapse!).to eq("queued" => 1)
      expect([ first.reload.state, second.reload.state ].sort).to eq(%w[claimed queued])
      described_class.lapse!
      expect([ first.reload.state, second.reload.state ]).to eq(%w[queued queued])
    end
  end
end
