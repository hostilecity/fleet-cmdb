require "rails_helper"

# P3-S03 (threat model R1): many simultaneous polls for one host claim a task exactly once. P3-X03 (R3, R4): many
# simultaneous starts of one task start it once, and the same result sent many times at once is stored once, while
# a different one at the same time is refused. Each request runs as the endpoint does, in its own transaction with
# the host row locked (AgentHostLock), on its own connection, outside the test transaction so each thread commits.
RSpec.describe "Concurrent task requests" do
  self.use_transactional_tests = false

  let(:pollers) { 8 }

  before do
    @host, @credential = enrolled_host(hostname: "race-tasks.example.lan")
    @host.update_columns(task_catalog_version: TaskCatalog.current.version, task_types_supported: TaskCatalog.current.types,
                         task_types_enabled: TaskCatalog.current.types, task_services_allowed: [], task_capabilities_reported_at: Time.current)
    @tasks = Array.new(3) { create_task(@host) }
  end

  after do
    connection = ActiveRecord::Base.connection
    connection.execute("SET session_replication_role = replica") # tasks, batches, audit, and hosts are protected
    [ TaskLateResult, Task, TaskBatch, AuditEntry, HostStatusEvent, AgentCredential, EnrollmentToken, Host, Operator ].each(&:delete_all)
  ensure
    connection&.execute("SET session_replication_role = DEFAULT")
  end

  # Runs the block once per poller, all released at once, each as one agent request; returns what each returned.
  def concurrently(count = pollers)
    gate = Queue.new
    threads = Array.new(count) do |i|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          gate.pop
          Task.transaction do
            host = AgentHostLock.lock!(host_id: @host.id, credential_id: AgentCredential.find_by!(host_id: @host.id).id)
            yield host, i
          end
        end
      end
    end
    count.times { gate << :go }
    threads.map(&:value)
  end

  def poll_concurrently = concurrently { |host| AgentTasks.poll!(host:)&.uuid }

  def result(outcome: "succeeded", report_id: SecureRandom.uuid)
    { "schema_version" => 1, "agent_version" => "0.3.0", "report_id" => report_id, "outcome" => outcome, "reason" => outcome == "failed" ? "nonzero_exit" : nil,
      "exit_status" => outcome == "failed" ? 1 : 0, "started_at" => "2026-01-01T12:00:05Z", "finished_at" => "2026-01-01T12:00:09Z",
      "details" => {}, "output" => "sent 3 reports\n", "output_truncated" => false }
  end

  def started_task
    task = Task.find_by!(uuid: poll_concurrently.compact.first)
    concurrently(1) { |host| AgentTasks.start!(host:, task: host.tasks.find(task.id), agent_started_at: Time.current) }
    task.reload
  end

  it "claims exactly one task, and every poll gets that same task" do
    delivered = poll_concurrently
    claimed = Task.where(host_id: @host.id, state: "claimed")
    expect(claimed.count).to eq(1)
    expect(delivered.uniq).to eq([ claimed.sole.uuid ])
    expect(AuditEntry.where(action: Audit::Actions::TASK_CLAIMED).count).to eq(1)
    expect(Task.where(host_id: @host.id, state: "queued").count).to eq(2)
  end

  it "starts a claimed task once when its start arrives many times at once, telling every request to run it" do
    task = Task.find_by!(uuid: poll_concurrently.first)
    states = concurrently { |host| AgentTasks.start!(host:, task: host.tasks.find(task.id), agent_started_at: Time.current).state }
    expect(states.uniq).to eq([ "running" ])
    expect(AuditEntry.where(action: Audit::Actions::TASK_STARTED, target_id: task.id).count).to eq(1)
  end

  it "stores one result when the same result arrives many times at once, as one duplicate after another" do
    task = started_task
    body = result
    outcomes = concurrently { |host| AgentTasks.record_result!(host:, task: host.tasks.find(task.id), payload: body) }
    expect(outcomes.count(&:applied)).to eq(pollers)
    expect(outcomes.count(&:duplicate)).to eq(pollers - 1)
    expect(outcomes.map(&:conflict).uniq).to eq([ nil ])
    expect(task.reload).to have_attributes(state: "succeeded", result_report_id: body["report_id"])
    expect(AuditEntry.where(action: Audit::Actions::TASK_SUCCEEDED, target_id: task.id).count).to eq(1)
  end

  it "keeps the first of two different results that arrive at once and refuses the other as a conflict (R4)" do
    task = started_task
    bodies = [ result(outcome: "succeeded"), result(outcome: "failed") ]
    outcomes = concurrently(2) { |host, i| AgentTasks.record_result!(host:, task: host.tasks.find(task.id), payload: bodies[i]) }
    expect(outcomes.map(&:conflict).compact).to eq([ "different_result" ])
    winner = outcomes.find { |outcome| outcome.conflict.nil? }
    expect(task.reload.state).to eq(winner.task.state).and be_in(%w[succeeded failed])
    expect(TaskLateResult.count).to eq(0)
  end
end
