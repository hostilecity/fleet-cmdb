require "rails_helper"

# #193, ADR 0026: summaries are synced and recounted once, at commit, with their rows locked in one sorted statement,
# and an advisory import only queues its hosts. So a transaction never waits on a summary row in the middle of its
# work, two transactions never deadlock on summaries, and two changing one host at once are both counted. Runs outside
# the test transaction so each thread commits on its own connection, and the deferred flush runs as in production.
RSpec.describe HostComplianceSummary do
  self.use_transactional_tests = false

  before { allow(CisEvaluationJob).to receive(:perform_later) }

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # hosts and audit are protected
    ids = Array(@hosts).map(&:id)
    advisory_ids = VulnerabilityFinding.where(host_id: ids).distinct.pluck(:advisory_id)
    VulnerabilityFinding.where(host_id: ids).delete_all
    Advisory.where(id: advisory_ids).delete_all
    [ CisResultChange, CisResult, HostVulnerabilityEvaluation, HostConfig, ConfigSnapshot, ConfigReportReceipt, InventorySnapshot, HostInventory,
      InventoryReportReceipt, HostStatusEvent, AgentCredential, EnrollmentToken, described_class ].each { |model| model.where(host_id: ids).delete_all }
    ActiveRecord::Base.connection.execute("DELETE FROM host_compliance_recounts")
    CisRule.update_all(current_version_id: nil)
    CisRuleVersion.delete_all
    CisRule.delete_all
    AuditEntry.where(target_type: %w[Host CisRule]).delete_all
    Host.where(id: ids).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  def summary(host = @host) = described_class.find(host.id)

  def evaluable_host
    @host = enrolled_host(hostname: "summary-race.example.lan").first
    @hosts = [ @host ]
    record_inventory(@host)
    define_cis_rules(cis_rule_hash)
    record_config(@host, "sshd.permitrootlogin" => ok_fact("yes"))
  end

  # Runs the block in its own transaction on another connection, holding it open until the main thread has gone on.
  def holding(seconds = 0.5, &block)
    written = Concurrent::CountDownLatch.new(1)
    thread = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        ActiveRecord::Base.transaction do
          block.call
          written.count_down
          sleep seconds
        end
      end
    end
    written.wait
    thread
  end

  # The block in a transaction that gives up on any lock it waits for longer than a second.
  def without_waiting(&block)
    ActiveRecord::Base.transaction do
      ActiveRecord::Base.connection.execute("SET LOCAL lock_timeout = '1s'")
      block.call
    end
  end

  def raise_severity(host, to: "critical") = Advisory.where(id: VulnerabilityFinding.where(host_id: host.id).select(:advisory_id)).update_all(severity: to)

  it "syncs and recounts when the transaction commits, not before" do
    @host = enrolled_host(hostname: "summary-deferred.example.lan").first
    @hosts = [ @host ]
    seen = nil
    open = holding(1.0) do
      findings!(@host, "high")
      seen = described_class.where(host_id: @host.id).pick(:vuln_high) # in the writing transaction: not yet
    end
    expect([ seen, summary.vuln_high ]).to eq([ 0, 0 ])
    open.join
    expect(summary.vuln_high).to eq(1)
    expect(ActiveRecord::Base.connection.select_value("SELECT count(*) FROM host_compliance_pending")).to eq(0)
  end

  it "lets a heartbeat change a host's liveness while an advisory import that moves its counts is open" do
    @host = enrolled_host(hostname: "summary-heartbeat.example.lan").first
    @hosts = [ @host ]
    findings!(@host, "high")
    Host.where(id: @host.id).update_all(liveness_status: "offline")
    import = holding(2.0) { raise_severity(@host) }
    without_waiting { Host.where(id: @host.id).update_all(liveness_status: "online", last_seen_at: Time.current) } # was a lock timeout
    expect(summary.status_rank).to eq(0)
    import.join
    expect(summary.vuln_high).to eq(1) # queued for the recount job
    ComplianceSummaryRecountJob.perform_now
    expect(summary).to have_attributes(vuln_high: 0, vuln_critical: 1)
    expect(described_class.drift).to be_empty
  end

  it "lets a CIS evaluation of a host finish while an advisory import that moves its counts is open" do
    evaluable_host
    findings!(@host, "high")
    import = holding(2.0) { raise_severity(@host) }
    without_waiting { CisEvaluation.evaluate!([ @host.id ]) }
    expect(summary.cis_failed).to eq(1)
    import.join
    ComplianceSummaryRecountJob.perform_now
    expect(summary).to have_attributes(cis_failed: 1, vuln_critical: 1)
    expect(described_class.drift).to be_empty
  end

  # The deadlock of the review: an import changing two advisories' severities, a host each, with liveness moving
  # the same two hosts in the other order, each in one transaction. Before, both locked summary rows mid-transaction
  # in opposite orders, and the import was rolled back.
  it "never deadlocks an advisory import against a liveness run moving the same hosts in the other order" do
    a = enrolled_host(hostname: "summary-a.example.lan").first
    b = enrolled_host(hostname: "summary-b.example.lan").first
    @hosts = [ a, b ]
    [ a, b ].each { |host| findings!(host, "high") }
    first = Concurrent::CountDownLatch.new(1)
    moved = Concurrent::CountDownLatch.new(1)
    errors = Queue.new
    import = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        ActiveRecord::Base.transaction do
          raise_severity(a)
          first.count_down
          moved.wait(2)
          sleep 0.2
          raise_severity(b)
        end
      rescue StandardError => e
        errors << e
      end
    end
    liveness = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        first.wait
        ActiveRecord::Base.transaction do
          Host.where(id: b.id).update_all(liveness_status: "stale")
          moved.count_down
          Host.where(id: a.id).update_all(liveness_status: "stale")
        end
      rescue StandardError => e
        errors << e
      end
    end
    [ import, liveness ].each(&:join)
    expect(errors).to be_empty
    expect([ summary(a).status_rank, summary(b).status_rank ]).to eq([ 1, 1 ])
    expect(ComplianceSummaryRecountJob.perform_now).to eq(2)
    expect([ summary(a).vuln_critical, summary(b).vuln_critical ]).to eq([ 1, 1 ])
    expect(described_class.drift).to be_empty
  end

  # A transaction already holding the host's summary row (here, a recount called directly, as the rebuild does)
  # makes the evaluation's flush wait, then count what it committed: without the lock first, the flush would write a
  # count from before it.
  it "counts a change committed while the evaluation's flush waited for the host's summary row" do
    evaluable_host
    findings!(@host, "low")
    other = holding(1.0) do
      VulnerabilityFinding.where(host_id: @host.id).update_all(state: "resolved", resolution: "fixed", resolved_at: Time.current)
      ActiveRecord::Base.connection.execute("SELECT host_compliance_summaries_refresh(ARRAY[#{@host.id}]::bigint[])")
    end
    CisEvaluation.evaluate!([ @host.id ])
    other.join
    expect(summary).to have_attributes(cis_failed: 1, cis_high: 1, vuln_low: 0)
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
    expect(summary(other)).to have_attributes(enrollment_state: "revoked", status_rank: 5, vuln_low: 1)
    expect(FleetCompliance.totals.vulns.values_at("high", "low")).to eq([ 0, 0 ])
    expect(described_class.drift).to be_empty
  end
end
