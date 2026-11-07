require "rails_helper"

# P2-S06: evaluating a host waits for a config report holding the host row, then evaluates what it committed;
# two evaluations of one host at once write each change once. Runs outside the test transaction so each thread
# commits on its own connection.
RSpec.describe CisEvaluation do
  self.use_transactional_tests = false

  before { allow(CisEvaluationJob).to receive(:perform_later) }

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # hosts and audit are protected
    [ CisResultChange, CisResult, HostConfig, ConfigSnapshot, ConfigReportReceipt, InventorySnapshot, HostInventory, InventoryReportReceipt,
      AgentCredential, EnrollmentToken ].each { |model| model.where(host_id: @host.id).delete_all }
    CisRule.update_all(current_version_id: nil)
    CisRuleVersion.delete_all
    CisRule.delete_all
    AuditEntry.where(target_type: %w[Host CisRule]).delete_all
    Host.where(id: @host.id).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  def changes = CisResultChange.where(host_id: @host.id).order(:id).pluck(:from_result, :to_result)

  it "waits for a config report holding the host row lock, then evaluates the snapshot it committed" do
    @host = enrolled_host(hostname: "cis-race.example.lan").first
    record_inventory(@host)
    define_cis_rules(cis_rule_hash)
    record_config(@host)
    described_class.evaluate!([ @host.id ])

    locked = Concurrent::CountDownLatch.new(1)
    committed_at = nil
    report = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Host.transaction do
          AgentHostLock.lock!(host_id: @host.id, credential_id: @host.agent_credentials.active.pick(:id))
          locked.count_down
          sleep 0.3
          record_config(@host, "sshd.permitrootlogin" => ok_fact("yes"))
        end
        committed_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
    locked.wait
    described_class.evaluate!([ @host.id ])
    evaluated_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    report.join

    expect(evaluated_at).to be > committed_at
    expect(CisResult.find_by!(host_id: @host.id).result).to eq("fail")
    expect(changes).to eq([ [ nil, "pass" ], %w[pass fail] ])
  end

  it "writes each change once when two evaluations of one host run at the same time" do
    @host = enrolled_host(hostname: "cis-twice.example.lan").first
    record_inventory(@host)
    define_cis_rules(cis_rule_hash)
    record_config(@host)

    threads = Array.new(2) { Thread.new { ActiveRecord::Base.connection_pool.with_connection { described_class.evaluate!([ @host.id ]) } } }
    threads.each(&:join)
    expect(changes).to eq([ [ nil, "pass" ] ])
  end
end
