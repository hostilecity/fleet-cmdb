require "rails_helper"

# P2-S14: a dry run takes no lock, so a config report in progress (holding the host row, as every agent write does)
# neither waits for it nor is waited for; it sees what is committed, in one read-only transaction. Runs outside
# the test transaction so each thread commits on its own connection.
RSpec.describe CisDryRun do
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

  it "does not wait for a config report holding the host row lock, and sees only what is committed" do
    @host = enrolled_host(hostname: "cis-dry-race.example.lan").first
    record_inventory(@host)
    define_cis_rules(cis_rule_hash)
    record_config(@host)
    CisEvaluation.evaluate!([ @host.id ])

    locked = Concurrent::CountDownLatch.new(1)
    previewed = Concurrent::CountDownLatch.new(1)
    report = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Host.transaction do
          AgentHostLock.lock!(host_id: @host.id, credential_id: @host.agent_credentials.active.pick(:id))
          CisResult.where(host_id: @host.id).lock.to_a # and the host's results, as an evaluation holds them
          record_config(@host, "sshd.permitrootlogin" => ok_fact("yes"))
          locked.count_down
          previewed.wait(10) # holds everything until the preview is done
        end
      end
    end
    locked.wait

    sql = []
    preview = nil
    ActiveSupport::Notifications.subscribed(->(*, payload) { sql << payload[:sql] }, "sql.active_record") do
      Timeout.timeout(5) { preview = described_class.call(cis_rule_hash(condition: { "ne" => "yes" })).preview }
    end
    previewed.count_down
    report.join

    expect(preview.changes).to eq([]) # the report's "yes" was not committed yet: the committed snapshot still passes
    expect(preview.counts).to have_attributes(hosts: 1, unchanged: 1)
    expect(sql).to include(a_string_matching(/\ABEGIN ISOLATION LEVEL REPEATABLE READ/), "SET TRANSACTION READ ONLY")
    expect(sql.grep(/FOR (UPDATE|SHARE|NO KEY UPDATE|KEY SHARE)|pg_advisory|LOCK TABLE/i)).to eq([])
  end
end
