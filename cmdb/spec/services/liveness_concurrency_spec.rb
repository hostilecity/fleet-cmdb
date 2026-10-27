require "rails_helper"

# P1-S09: the evaluation job is "safe to run concurrently or twice". Runs outside the test transaction so each
# thread commits on its own connection.
RSpec.describe "Concurrent liveness evaluation" do
  self.use_transactional_tests = false

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # hosts and audit are protected
    HostStatusEvent.where(host_id: @hosts.map(&:id)).delete_all
    AuditEntry.where(target_type: "Host", target_id: @hosts.map(&:id)).delete_all
    AgentCredential.where(host_id: @hosts.map(&:id)).delete_all
    EnrollmentToken.where(host_id: @hosts.map(&:id)).delete_all
    Host.where(id: @hosts.map(&:id)).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  def prepare_hosts(start)
    @hosts = Array.new(3) { |i| enrolled_host(hostname: "race-#{i}.example.lan").first }
    @hosts.each { |h| Host.transaction { Liveness.record_heartbeat!(h, agent_version: "0.1.0", agent_schema_version: 1, agent_time: start) } }
    Host.where(id: @hosts.map(&:id)).update_all(last_seen_at: start - 20.minutes)
  end

  it "writes each transition once when a second run overlaps an uncommitted first run" do
    start = Time.current
    prepare_hosts(start)
    first_done = Queue.new
    release = Queue.new

    first = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Host.transaction do
          written = Liveness.evaluate!(now: start)
          first_done << written
          release.pop # hold the transaction (and its row locks) open while the second run happens
          written
        end
      end
    end
    expect(first_done.pop).to eq(3)

    second = Thread.new { ActiveRecord::Base.connection_pool.with_connection { Liveness.evaluate!(now: start) } }
    second_written = second.join(10)&.value # SKIP LOCKED: must not wait for the first run
    release << :go
    first.join

    expect(second_written).to eq(0)
    expect(HostStatusEvent.where(host_id: @hosts.map(&:id), reason: "evaluation").group(:host_id).count.values).to eq([ 1, 1, 1 ])
    expect(Liveness.evaluate!(now: start)).to eq(0) # and a later run has nothing left to do
  ensure
    release << :go if release&.empty?
  end

  it "skips a host whose row is held by a heartbeat in flight, and picks it up on the next run" do
    start = Time.current
    prepare_hosts(start)
    held = @hosts.first
    locked = Queue.new
    release = Queue.new
    holder = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Host.transaction do
          Host.where(id: held.id).lock.pick(:id)
          locked << true
          release.pop
        end
      end
    end
    locked.pop

    evaluator = Thread.new { ActiveRecord::Base.connection_pool.with_connection { Liveness.evaluate!(now: start) } }
    expect(evaluator.join(10)&.value).to eq(2)
    release << :go
    holder.join
    expect(Liveness.evaluate!(now: start)).to eq(1)
    expect(Host.where(id: @hosts.map(&:id)).pluck(:liveness_status).uniq).to eq([ "offline" ])
  ensure
    release << :go if release&.empty?
  end
end
