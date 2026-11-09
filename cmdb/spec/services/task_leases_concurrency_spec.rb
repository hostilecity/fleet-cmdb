require "rails_helper"

# P3-S05 (threat model L6): the expiry and lease jobs are safe to run several at once and alongside polls. Each runs
# on its own connection, outside the test transaction, so each commits.
RSpec.describe "Concurrent task expiry and lease runs" do
  self.use_transactional_tests = false

  let(:runners) { 4 }

  before do
    operator = create(:operator)
    @hosts = Array.new(4) { |i| task_host(hostname: "race-leases-#{i}.example.lan", last_seen_at: 1.hour.ago) }
    @expired = @hosts.map { |host| TaskBatches.create!({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, operator:, now: 2.days.ago).tasks.sole }
    @running = @hosts.map do |host|
      task = create_task(host, operator:)
      task.claim!(actor: host, lease_expires_at: 1.hour.ago)
      task.start!(actor: host, lease_expires_at: 1.minute.ago)
    end
  end

  after do
    connection = ActiveRecord::Base.connection
    connection.execute("SET session_replication_role = replica") # tasks, batches, audit, and hosts are protected
    [ TaskLateResult, Task, TaskBatch, AuditEntry, Host, Operator ].each(&:delete_all)
  ensure
    connection&.execute("SET session_replication_role = DEFAULT")
  end

  def run_concurrently(&block)
    gate = Queue.new
    threads = Array.new(runners) do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          gate.pop
          block.call
        end
      end
    end
    runners.times { gate << :go }
    threads.map(&:value)
  end

  it "expires each task once and ends each lease once, however many runs overlap" do
    run_concurrently { [ TaskLeases.expire!, TaskLeases.lapse! ] }
    expect(Task.where(id: @expired.map(&:id)).pluck(:state).uniq).to eq(%w[expired])
    expect(Task.where(id: @running.map(&:id)).pluck(:state, :reason).uniq).to eq([ %w[failed lease_expired] ])
    expect(AuditEntry.where(action: Audit::Actions::TASK_EXPIRED).count).to eq(@expired.size)
    expect(AuditEntry.where(action: Audit::Actions::TASK_FAILED).count).to eq(@running.size)
  end
end
