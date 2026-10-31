require "rails_helper"

# P1-S05: "A token can be redeemed exactly once, including under concurrent requests." This runs outside the
# test transaction so each thread really commits on its own connection and the row lock is exercised.
#
# Each thread works only on records it loads itself, on its own connection, as concurrent requests do. A host
# object shared between threads is not thread-safe: one thread's lock! could see another thread's unsaved
# attribute changes and raise, which made this spec fail intermittently (#69).
RSpec.describe "Concurrent enrollment" do
  self.use_transactional_tests = false

  after do
    # Hosts and audit entries are protected by append-only triggers; disable triggers for this session to
    # remove only the rows this spec created. Requires a superuser, which test databases use.
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica")
    AuditEntry.where(target_type: "Host", target_id: @host_id).delete_all
    AgentCredential.where(host_id: @host_id).delete_all
    EnrollmentToken.where(host_id: @host_id).delete_all
    Host.where(id: @host_id).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  # Registers the host on this thread's connection and keeps only its id, so no record is shared with the threads.
  def register_host
    host, token = Enrollment::RegisterHost.call({ name: "Race", hostname: "race.example.lan" }, actor: Audit::SYSTEM)
    @host_id = host.id
    token
  end

  it "redeems a token exactly once when several agents race" do
    token = register_host
    gate = Concurrent::CountDownLatch.new(1)
    results = Array.new(4) do # the test pool has 5 connections; this thread holds one
      Thread.new do
        gate.wait
        ActiveRecord::Base.connection_pool.with_connection do
          Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
          :redeemed
        rescue AgentApi::EnrollmentTokenInvalid
          :rejected
        end
      end
    end
    gate.count_down
    outcomes = results.map(&:value)

    expect(outcomes.count(:redeemed)).to eq(1)
    expect(outcomes.count(:rejected)).to eq(3)
    expect(AgentCredential.where(host_id: @host_id).count).to eq(1)
    expect(Host.find(@host_id).enrollment_state).to eq("active")
  end

  it "does not deadlock when a token is issued while another is being redeemed" do
    token = register_host
    gate = Concurrent::CountDownLatch.new(1)
    threads = Array.new(4) do |i| # the test pool has 5 connections; this thread holds one
      Thread.new do
        gate.wait
        ActiveRecord::Base.connection_pool.with_connection do
          if i.even?
            Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
          else
            Enrollment::IssueToken.call(host: Host.find(@host_id), actor: Audit::SYSTEM) # loaded fresh on this thread
          end
          :ok
        rescue AgentApi::EnrollmentTokenInvalid
          :rejected
        rescue ActiveRecord::Deadlocked
          :deadlocked
        end
      end
    end
    gate.count_down
    outcomes = threads.map(&:value)

    expect(outcomes).not_to include(:deadlocked)
    expect(AgentCredential.where(host_id: @host_id, state: "active").count).to be <= 1
  end
end
