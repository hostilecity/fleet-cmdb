require "rails_helper"

# Two requests of one operator at once (VT-OVERRIDES #261, epic decision 37; review of #299): both pass the form's
# check (6 host decisions each, none recorded yet), and each counts the operator's decisions again under the
# operator's row lock, so the second sees the first's 6 and needs the second factor. Without the lock, both counts
# read 0 and 12 decisions would be saved with no code. Runs outside the test transaction so each thread commits on its
# own connection. The hosts' own checks (Candidates) are stubbed: this is about the count, not the findings.
RSpec.describe FindingDecisions do
  self.use_transactional_tests = false

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # decisions, hosts, and audit are protected
    FindingDecision.where(host_id: @hosts.map(&:id)).delete_all
    AuditEntry.where(target_type: "Host", target_id: @hosts.map(&:id)).delete_all
    AuditEntry.where(actor_type: "operator", actor_id: @operator.id).delete_all
    [ AgentCredential, EnrollmentToken ].each { |model| model.where(host_id: @hosts.map(&:id)).delete_all }
    Host.where(id: @hosts.map(&:id)).delete_all
    Advisory.where(id: @advisory.id).delete_all
    Operator.where(id: @operator.id).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  it "counts two requests of one operator one after the other under the operator's lock" do
    @operator = create(:operator)
    @advisory = Advisory.create!(advisory_id: "DEBIAN-CVE-2026-95001", source: "test", summary: "Example.", severity: "high", modified_at: Time.current)
    @hosts = Array.new(12) { |i| enrolled_host(hostname: "race-#{i}.example.lan").first }
    signals = described_class.signals([ @advisory.id ]).fetch(@advisory.id)
    allow(FindingDecisions::Candidates).to receive(:load) do |_, ids, **|
      Host.where(id: ids).order(:id).map do |host|
        FindingDecisions::Candidates::Candidate.new(host:, findings: [], rule: "L5", listening: "none", firewall: nil, decision: nil, problem: nil, signals:)
      end
    end
    # Hold each count a moment, so both requests are inside their transactions at once.
    allow(described_class).to receive(:recent_count).and_wrap_original { |original, *args, **kw| original.call(*args, **kw).tap { sleep 0.3 } }
    gate = Concurrent::CountDownLatch.new(1)
    threads = @hosts.each_slice(6).map do |hosts|
      Thread.new do
        gate.wait
        ActiveRecord::Base.connection_pool.with_connection do
          described_class.record!(operator: @operator, host: hosts.first, advisory: @advisory, stepped_up: false,
                                  params: { kind: "accepted", reason: "a reason long enough", expires_on: (Date.current + 10).iso8601, host_ids: hosts.map(&:id) })
        end
      rescue StandardError => e
        e
      end
    end
    gate.count_down
    outcomes = threads.map(&:value)

    expect(outcomes.grep(Exception)).to eq([])
    expect(outcomes.count(&:saved?)).to eq(1)
    expect(outcomes.reject(&:saved?).sole.errors[:second_factor_code]).to start_with("You have recorded 6 host decisions in the last 15 minutes")
    expect(FindingDecision.where(created_by: @operator).count).to eq(6)
  end
end
