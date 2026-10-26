require "rails_helper"

# P1-S05: "A token can be redeemed exactly once, including under concurrent requests." This runs outside the
# test transaction so each thread really commits on its own connection and the row lock is exercised.
RSpec.describe "Concurrent enrollment" do
  self.use_transactional_tests = false

  after do
    # Hosts and audit entries are protected by append-only triggers; disable triggers for this session to
    # remove only the rows this spec created. Requires a superuser, which test databases use.
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica")
    AuditEntry.where(target_type: "Host", target_id: @host.id).delete_all
    AgentCredential.where(host_id: @host.id).delete_all
    EnrollmentToken.where(host_id: @host.id).delete_all
    Host.where(id: @host.id).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  it "redeems a token exactly once when several agents race" do
    @host, token = Enrollment::RegisterHost.call({ name: "Race", hostname: "race.example.lan" }, actor: Audit::SYSTEM)
    gate = Concurrent::CountDownLatch.new(1)
    results = Array.new(6) do
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
    expect(outcomes.count(:rejected)).to eq(5)
    expect(AgentCredential.where(host_id: @host.id).count).to eq(1)
    expect(@host.reload.enrollment_state).to eq("active")
  end
end
