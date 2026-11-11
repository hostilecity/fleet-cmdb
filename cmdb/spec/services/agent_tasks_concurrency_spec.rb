require "rails_helper"

# P3-S03 (threat model R1): many simultaneous polls for one host claim a task exactly once. Each poll runs as the
# endpoint does, in its own transaction with the host row locked (AgentHostLock), on its own connection, outside
# the test transaction so each thread commits.
RSpec.describe "Concurrent task polls" do
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

  def poll_concurrently
    gate = Queue.new
    threads = Array.new(pollers) do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          gate.pop
          Task.transaction do
            host = AgentHostLock.lock!(host_id: @host.id, credential_id: AgentCredential.find_by!(host_id: @host.id).id)
            AgentTasks.poll!(host:)&.uuid
          end
        end
      end
    end
    pollers.times { gate << :go }
    threads.map(&:value)
  end

  it "claims exactly one task, and every poll gets that same task" do
    delivered = poll_concurrently
    claimed = Task.where(host_id: @host.id, state: "claimed")
    expect(claimed.count).to eq(1)
    expect(delivered.uniq).to eq([ claimed.sole.uuid ])
    expect(AuditEntry.where(action: Audit::Actions::TASK_CLAIMED).count).to eq(1)
    expect(Task.where(host_id: @host.id, state: "queued").count).to eq(2)
  end
end
