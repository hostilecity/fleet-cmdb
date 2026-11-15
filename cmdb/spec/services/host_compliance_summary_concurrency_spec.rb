require "rails_helper"

# #193: two transactions changing one host's compliance at once leave a summary that counts both, whichever commits
# first, because a recount locks the host's summary row before it counts. Runs outside the test transaction so each
# thread commits on its own connection.
RSpec.describe HostComplianceSummary do
  self.use_transactional_tests = false

  before { allow(CisEvaluationJob).to receive(:perform_later) }

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # hosts and audit are protected
    ids = Array(@hosts).map(&:id)
    advisories = VulnerabilityFinding.where(host_id: ids).select(:advisory_id)
    Advisory.where(id: advisories).then { |scope| scope.ids }.then do |advisory_ids|
      VulnerabilityFinding.where(host_id: ids).delete_all
      Advisory.where(id: advisory_ids).delete_all
    end
    [ CisResultChange, CisResult, HostVulnerabilityEvaluation, HostConfig, ConfigSnapshot, ConfigReportReceipt, InventorySnapshot, HostInventory,
      InventoryReportReceipt, AgentCredential, EnrollmentToken, described_class ].each { |model| model.where(host_id: ids).delete_all }
    CisRule.update_all(current_version_id: nil)
    CisRuleVersion.delete_all
    CisRule.delete_all
    AuditEntry.where(target_type: %w[Host CisRule]).delete_all
    Host.where(id: ids).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  def summary = described_class.find(@host.id)

  def evaluable_host
    @host = enrolled_host(hostname: "summary-race.example.lan").first
    @hosts = [ @host ]
    record_inventory(@host)
    define_cis_rules(cis_rule_hash)
    record_config(@host, "sshd.permitrootlogin" => ok_fact("yes"))
  end

  # Runs the block in its own transaction on another connection, holding it open until the main thread is waiting.
  def holding(&block)
    written = Concurrent::CountDownLatch.new(1)
    thread = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        ActiveRecord::Base.transaction do
          block.call
          written.count_down
          sleep 0.5
        end
      end
    end
    written.wait
    thread
  end

  # An advisory import's new severity takes no lock on the host, so it is not serialised with an evaluation by the host
  # row: only by the summary row (without the lock-first, each would write its own stale count over the other's).
  def raise_severity = Advisory.where(id: VulnerabilityFinding.where(host_id: @host.id).select(:advisory_id)).update_all(severity: "critical")

  it "counts a new advisory severity committed while a CIS evaluation of the host waited for its summary row" do
    evaluable_host
    findings!(@host, "high")
    import = holding { raise_severity }
    CisEvaluation.evaluate!([ @host.id ])
    import.join
    expect(summary).to have_attributes(cis_failed: 1, cis_high: 1, vuln_high: 0, vuln_critical: 1)
    expect(described_class.drift).to be_empty
  end

  it "counts a CIS failure committed while an advisory import waited for the host's summary row" do
    evaluable_host
    findings!(@host, "high")
    evaluation = holding { CisEvaluation.evaluate!([ @host.id ]) }
    raise_severity
    evaluation.join
    expect(summary).to have_attributes(cis_failed: 1, cis_high: 1, vuln_high: 0, vuln_critical: 1)
    expect(described_class.drift).to be_empty
  end

  it "keeps the counts of two evaluations, a rule disabled, and a finding resolved, all at once" do
    evaluable_host
    findings!(@host, "low", "medium")
    rule = CisRule.sole
    threads = [
      Thread.new { ActiveRecord::Base.connection_pool.with_connection { CisEvaluation.evaluate!([ @host.id ]) } },
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) }
          CisEvaluation.evaluate!([ @host.id ], rule_ids: [ rule.id ])
        end
      end,
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          VulnerabilityFinding.joins(:advisory).where(host_id: @host.id, advisories: { severity: "low" })
                              .update_all(state: "resolved", resolution: "fixed", resolved_at: Time.current)
        end
      end
    ]
    threads.each(&:join)
    expect(summary).to have_attributes(cis_failed: 0, cis_counted: 0, vuln_low: 0, vuln_medium: 1)
    expect(described_class.drift).to be_empty
  end

  it "keeps a host retired or revoked while another transaction recounts it" do
    @host = enrolled_host(hostname: "summary-retire.example.lan").first
    other = enrolled_host(hostname: "summary-revoke.example.lan").first
    @hosts = [ @host, other ]
    finding = holding { findings!(@host, "high") && findings!(other, "low") }
    @host.retire!(actor: Audit::SYSTEM)
    other.revoke!(actor: Audit::SYSTEM)
    finding.join
    expect(summary).to have_attributes(enrollment_state: "retired", vuln_high: 1)
    expect(described_class.find(other.id)).to have_attributes(enrollment_state: "revoked", status_rank: 5, vuln_low: 1)
    expect(FleetCompliance.totals.vulns.values_at("high", "low")).to eq([ 0, 0 ])
    expect(described_class.drift).to be_empty
  end
end
