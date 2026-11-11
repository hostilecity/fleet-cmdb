require "rails_helper"

# P3-S05: what a cancel does in each state (FR-3.2, AC-3.6; mockups cancel.html and batch-partial.html, owner
# decisions Q17 and Q23).
RSpec.describe TaskCancellation do
  let(:operator) { create(:operator) }
  let(:other_operator) { create(:operator) }

  def batch_of(type, hosts)
    allow_restart("nginx.service") if type == "restart_service" && !TaskAllowedService.exists?
    parameters = type == "restart_service" ? { "service" => "nginx.service" } : {}
    create_task_batch(hosts, type:, parameters:, operator:)
  end

  def run(task)
    task.claim!(actor: task.host, lease_expires_at: 5.minutes.from_now)
    task.start!(actor: task.host, lease_expires_at: 1.hour.from_now)
  end

  def poll(host) = Task.transaction { AgentTasks.poll!(host: Host.lock.find(host.id)) }

  describe ".cancel_task!" do
    it "cancels a queued task at once, with the operator as actor, and it is never delivered (AC-3.6)" do
      task = create_task(task_host, operator:)
      result = described_class.cancel_task!(task, operator: other_operator)
      expect(result).to have_attributes(outcome: :cancelled, cancelled: [ task ])
      expect(task.reload).to have_attributes(state: "cancelled", cancel_requested_at: nil)
      expect(AuditEntry.where(action: Audit::Actions::TASK_CANCELLED, target_id: task.id).sole).to have_attributes(actor_type: "operator", actor_id: other_operator.id)
      expect(poll(task.host)).to be_nil
    end

    it "cancels a claimed task the agent has not started, and refuses its start (threat model L3)" do
      task = create_task(task_host, operator:)
      expect(poll(task.host)).to eq(task)
      described_class.cancel_task!(task, operator:)
      started = Task.transaction { AgentTasks.start!(host: task.host, task: task.reload, agent_started_at: Time.current) }
      expect(started.state).to eq("cancelled")
    end

    it "records a stop request for a running interruptible task, and the agent's cancelled result ends it" do
      task = run(create_task(task_host, operator:))
      result = described_class.cancel_task!(task, operator:)
      expect(result).to have_attributes(outcome: :stop_requested, stopping: [ task ], cancelled: [])
      expect(task.reload).to have_attributes(state: "running", cancel_requested_by: operator)
      expect(AgentTasks.cancel_directive(task.host)).to eq(id: task.uuid)
      expect(described_class.cancel_task!(task, operator: other_operator).outcome).to eq(:already_requested)
      expect(AuditEntry.where(action: Audit::Actions::TASK_CANCEL_REQUESTED).count).to eq(1)
    end

    it "lets a running non-interruptible task finish, records the request, and cancels what has not started in its batch (Q17)" do
      hosts = Array.new(4) { task_host }
      batch = batch_of("apply_package_updates", hosts)
      running, claimed, queued, done = batch.tasks
      run(running)
      poll(claimed.host)
      run(done).succeed!(actor: done.host, exit_status: 0)

      result = described_class.cancel_task!(running, operator:)
      expect(result.outcome).to eq(:cancel_requested)
      expect(result.cancelled).to contain_exactly(claimed, queued)
      expect(running.reload).to have_attributes(state: "running", cancel_requested_by: operator)
      expect([ claimed.reload.state, queued.reload.state, done.reload.state ]).to eq(%w[cancelled cancelled succeeded])
      expect(AgentTasks.cancel_directive(running.host)).to be_nil # it cannot be stopped, so the agent is not told to
      running.succeed!(actor: running.host, exit_status: 0)
      expect(running.reload).to have_attributes(state: "succeeded", cancel_requested?: true) # its real state, with the request beside it
    end

    it "records a cancel request for a lone running non-interruptible task" do
      task = run(batch_of("restart_service", [ task_host ]).tasks.sole)
      expect(described_class.cancel_task!(task, operator:)).to have_attributes(outcome: :cancel_requested, running_on: [ task ], cancelled: [])
    end

    it "changes nothing on a finished task" do
      task = create_task(task_host, operator:)
      task.expire!(actor: Audit::SYSTEM)
      expect(described_class.cancel_task!(task, operator:)).to have_attributes(outcome: :finished, finished: [ task ])
      expect(AuditEntry.where(actor_type: "operator", action: [ Audit::Actions::TASK_CANCELLED, Audit::Actions::TASK_CANCEL_REQUESTED ])).to be_empty
    end
  end

  describe ".cancel_batch!" do
    it "cancels the waiting tasks, asks the running ones to stop where they can, and leaves the finished ones (cancel.html)" do
      hosts = Array.new(5) { task_host }
      batch = batch_of("refresh_reports", hosts.first(2))
      stopping, waiting = batch.tasks
      run(stopping)
      packages = batch_of("apply_package_updates", hosts.last(3))
      unstoppable, queued, finished = packages.tasks
      run(unstoppable)
      run(finished).fail!(actor: finished.host, reason: "nonzero_exit", exit_status: 1)

      first = described_class.cancel_batch!(batch.batch, operator:)
      expect(first).to have_attributes(cancelled: [ waiting ], stopping: [ stopping ], running_on: [], finished: [])
      second = described_class.cancel_batch!(packages.batch, operator:)
      expect(second).to have_attributes(cancelled: [ queued ], stopping: [], running_on: [ unstoppable ], finished: [ finished ])
      expect([ unstoppable.reload.state, queued.reload.state, finished.reload.state ]).to eq(%w[running cancelled failed])
      expect(described_class.cancel_batch!(packages.batch, operator:)).to have_attributes(cancelled: [], running_on: []) # once
      expect(AuditEntry.where(action: Audit::Actions::TASK_CANCEL_REQUESTED).count).to eq(2)
    end
  end

  describe "when a host's credential is revoked, it starts re-enrolling, or it is retired (threat model V9)" do
    %i[revoke begin_reenrollment retire].each do |event|
      it "#{event}: cancels its queued and claimed tasks with the same actor, and leaves a running one" do
        host = task_host
        queued, claimed, running = Array.new(3) { create_task(host, operator:) }
        claimed.claim!(actor: host, lease_expires_at: 5.minutes.from_now)
        run(running)
        other = create_task(task_host, operator:)
        host.public_send(:"#{event}!", actor: other_operator)
        expect([ queued, claimed, running, other ].map { |task| task.reload.state }).to eq(%w[cancelled cancelled running queued])
        expect(AuditEntry.where(action: Audit::Actions::TASK_CANCELLED).pluck(:target_id, :actor_type, :actor_id))
          .to contain_exactly([ queued.id, "operator", other_operator.id ], [ claimed.id, "operator", other_operator.id ])
      end
    end
  end
end
