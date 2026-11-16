require "rails_helper"

# HostComplianceSummary (#193): the database keeps every host's row equal to a fresh count of the rows the host pages
# show, whichever code writes them, and copies the host fields the fleet list sorts by.
RSpec.describe HostComplianceSummary do
  include ActiveJob::TestHelper

  def summary(host) = described_class.find(host.id)

  # The counts, from the rows, counted again in Ruby as the host tabs count them.
  def expected(host)
    results = CisResult.where(host_id: host.id).group(:result).count
    { "cis_passed" => results.fetch("pass", 0), "cis_failed" => results.fetch("fail", 0), "cis_not_readable" => results.fetch("not_readable", 0),
      "vuln_evaluated" => HostVulnerabilityEvaluation.exists?(host_id: host.id, state: "evaluated") }
      .merge(expected_cis(host).transform_keys { |s| "cis_#{s}" }, expected_vulns(host).transform_keys { |s| "vuln_#{s}" })
  end

  def counts(host) = summary(host).attributes.slice(*expected(host).keys)

  def expect_consistent(*hosts)
    hosts.each { |host| expect(counts(host)).to eq(expected(host)) }
    expect(described_class.drift).to be_empty
  end

  def version_of(host) = described_class.where(host_id: host.id).pick(Arel.sql("xmin::text"))

  it "has a row for every host from its creation, with the fields the fleet list sorts and filters by" do
    pending_host = create(:host, name: "Media Server", hostname: "vm-01.example.lan", tags: %w[media lab])
    expect(summary(pending_host)).to have_attributes(enrollment_state: "pending", status_rank: 4, name_key: "media server", hostname: "vm-01.example.lan",
                                                     tags_key: "media,lab", agent_key: nil, os_name: nil, cis_counted: 0, vuln_open: 0,
                                                     pass_rate: nil, nothing_evaluated: true, fleet_cis_key: nil, fleet_vulns_key: nil)
    host, = enrolled_host(name: "Web A", hostname: "vm-02.example.lan", tags: [])
    expect(summary(host)).to have_attributes(enrollment_state: "active", status_rank: 3, tags_key: nil, agent_key: [ 0, 1, 0 ])
    record_heartbeat(host, agent_version: "1.10.2-rc.1+build.5")
    record_inventory(host, os: { "id" => "debian", "version_id" => "13", "pretty_name" => "Debian GNU/Linux 13 (trixie)" })
    expect(summary(host)).to have_attributes(status_rank: 0, agent_key: [ 1, 10, 2 ], os_name: "Debian GNU/Linux 13 (trixie)")
    host.edit!({ name: "Web B", hostname: "vm-03.example.lan", tags: "web" }, actor: Audit::SYSTEM)
    expect(summary(host)).to have_attributes(name_key: "web b", hostname: "vm-03.example.lan", tags_key: "web")
    Host.where(id: host.id).update_all(agent_version: "not a version")
    HostLiveness.where(host_id: host.id).update_all(liveness_status: "offline")
    expect(summary(host)).to have_attributes(agent_key: nil, status_rank: 2)
    host.revoke!(actor: Audit::SYSTEM)
    expect(summary(host)).to have_attributes(enrollment_state: "revoked", status_rank: 5)
    host.retire!(actor: Audit::SYSTEM)
    expect(summary(host)).to have_attributes(enrollment_state: "retired", status_rank: 5)
    HostInventory.where(host_id: host.id).delete_all
    expect(summary(host).os_name).to be_nil
    expect(summary(host)).to be_readonly
  end

  it "follows CIS evaluation, a rule disabled and enabled again, a new rule version, and a rule deleted" do
    host, = enrolled_host
    other, = enrolled_host
    [ host, other ].each { |h| record_inventory(h) }
    root, banner = define_cis_rules(cis_rule_hash, cis_rule_hash(key: "passwords-off", fact: "sshd.passwordauthentication", condition: { "eq" => false }, severity: "low"))
    record_config(host, "sshd.permitrootlogin" => ok_fact("yes"), "sshd.passwordauthentication" => ok_fact(true))
    record_config(other)
    CisEvaluation.evaluate!([ host.id, other.id ])
    expect(summary(host)).to have_attributes(cis_failed: 2, cis_high: 1, cis_low: 1, pass_rate: 0)
    expect_consistent(host, other)

    CisRule.transaction { root.disable!(actor: Audit::SYSTEM) }
    CisEvaluation.evaluate!([ host.id, other.id ], rule_ids: [ root.id ])
    expect(summary(host)).to have_attributes(cis_failed: 1, cis_high: 0, cis_counted: 1)
    expect_consistent(host, other)

    CisRule.transaction { root.enable!(actor: Audit::SYSTEM) }
    CisEvaluation.evaluate!([ host.id, other.id ], rule_ids: [ root.id ])
    expect(summary(host)).to have_attributes(cis_failed: 2, cis_high: 1)
    expect_consistent(host, other)

    CisRule.transaction { root.revise!(CisRules::Definition.from_h(cis_rule_hash(severity: "critical")), actor: Audit::SYSTEM) }
    expect(summary(host)).to have_attributes(cis_high: 1, cis_critical: 0) # still counted under the version that failed
    CisEvaluation.evaluate!([ host.id, other.id ], rule_ids: [ root.id ])
    expect(summary(host)).to have_attributes(cis_high: 0, cis_critical: 1)
    expect_consistent(host, other)

    # There is no rule deletion in the application; deleting one in SQL keeps the counts right all the same.
    CisRule.where(id: banner.id).update_all(current_version_id: nil)
    [ CisResultChange, CisResult, CisRuleVersion ].each { |model| model.where(cis_rule_id: banner.id).delete_all }
    CisRule.where(id: banner.id).delete_all
    expect(summary(host)).to have_attributes(cis_failed: 1, cis_low: 0)
    expect_consistent(host, other)
  end

  it "follows a fleet-wide evaluation run that writes many hosts' results in each batch and chunk (#204)" do
    hosts = Array.new(5) { |i| enrolled_host(name: "Chunked #{i}").first }
    hosts.each { |host| record_inventory(host) }
    rule, = define_cis_rules(cis_rule_hash(severity: "critical"))
    hosts.each_with_index { |host, i| record_config(host, "sshd.permitrootlogin" => ok_fact(i.even? ? "yes" : "no")) }
    stub_const("EvaluationRun::BATCH_SIZE", 3)
    stub_const("CisEvaluation::LOCK_CHUNK", 2)
    perform_enqueued_jobs { EvaluationRun.start!("cis_rules", "rule_ids" => [ rule.id ]) }
    expect(EvaluationRun.order(:id).last).to have_attributes(state: "finished", batch_count: 2)
    expect(hosts.map { |host| summary(host).cis_critical }).to eq([ 1, 0, 1, 0, 1 ])
    expect_consistent(*hosts)
  end

  it "counts a failure that names no rule version under the rule's current version, which can change" do
    host, = enrolled_host
    rule, = define_cis_rules(cis_rule_hash(severity: "low"))
    CisResult.insert_all!([ { host_id: host.id, cis_rule_id: rule.id, result: "fail", evaluated_at: Time.current, changed_at: Time.current } ])
    expect(summary(host).cis_low).to eq(1)
    CisRule.transaction { rule.revise!(CisRules::Definition.from_h(cis_rule_hash(severity: "high")), actor: Audit::SYSTEM) }
    expect(summary(host)).to have_attributes(cis_low: 0, cis_high: 1)
    expect_consistent(host)
  end

  it "follows findings opening, resolving, and reopening, an advisory's new severity, and the evaluation state" do
    host, = enrolled_host
    other, = enrolled_host
    findings!(host, "critical", "low")
    findings!(host, "high", state: "resolved")
    findings!(other, "medium")
    expect(summary(host)).to have_attributes(vuln_critical: 1, vuln_low: 1, vuln_high: 0, vuln_open: 2, fleet_vulns_key: 2)
    expect_consistent(host, other)

    critical = VulnerabilityFinding.joins(:advisory).find_by!(host_id: host.id, advisories: { severity: "critical" })
    critical.update!(state: "resolved", resolution: "fixed", resolved_at: Time.current)
    resolved = VulnerabilityFinding.joins(:advisory).find_by!(host_id: host.id, advisories: { severity: "high" })
    resolved.update!(state: "reopened", resolution: nil, reopened_at: Time.current)
    expect(summary(host)).to have_attributes(vuln_critical: 0, vuln_high: 1)
    expect_consistent(host, other)

    # As an advisory import writes them: an upsert of the advisory rows. The hosts are queued, not recounted in the
    # import's transaction, and the recount job brings them up to date.
    advisory = resolved.advisory
    Advisory.upsert_all([ advisory.attributes.except("id").merge("severity" => "unknown") ], unique_by: :advisory_id, record_timestamps: false)
    Advisory.where(id: critical.advisory_id).update_all(severity: "low") # resolved: nothing queued
    expect(summary(host)).to have_attributes(vuln_high: 1, vuln_unknown: 0)
    expect(described_class.queued).to eq(1)
    expect(described_class.drift).to be_empty # queued hosts are known to be behind
    expect(ComplianceSummaryRecountJob.perform_now).to eq(1)
    expect(summary(host)).to have_attributes(vuln_high: 0, vuln_unknown: 1, vuln_low: 1)
    expect(described_class.queued).to eq(0)
    expect_consistent(host, other)

    expect(summary(host)).to have_attributes(vuln_evaluated: false, fleet_vulns_key: 2)
    vulns_evaluated!(host)
    expect(summary(host).vuln_evaluated).to be(true)
    HostVulnerabilityEvaluation.where(host_id: host.id).update_all(state: "not_evaluated", reason: "no_package_report")
    expect(summary(host).vuln_evaluated).to be(false)
    HostVulnerabilityEvaluation.where(host_id: host.id).delete_all
    VulnerabilityFinding.where(host_id: host.id).delete_all
    expect(summary(host)).to have_attributes(vuln_evaluated: false, vuln_open: 0, fleet_vulns_key: nil, nothing_evaluated: true)
    expect_consistent(host, other)
  end

  it "writes nothing to the summary when evaluation, matching, or a heartbeat changes nothing it shows" do
    host, = enrolled_host
    record_inventory(host)
    define_cis_rules(cis_rule_hash)
    record_config(host)
    CisEvaluation.evaluate!([ host.id ])
    record_heartbeat(host)
    findings!(host, "low")
    before = version_of(host)
    CisEvaluation.evaluate!([ host.id ])
    record_heartbeat(host)
    VulnerabilityFinding.where(host_id: host.id).update_all(fixed_version: "1.0-2", updated_at: Time.current)
    expect(version_of(host)).to eq(before)
  end

  it "keeps revoked and retired hosts' counts out of the compliance page and its totals, and the counts for a re-enrolled host" do
    host, = enrolled_host
    findings!(host, "high")
    expect(FleetCompliance.totals).to have_attributes(hosts: 1, vulns: include("high" => 1))
    host.revoke!(actor: Audit::SYSTEM)
    expect(FleetCompliance.totals).to have_attributes(hosts: 0, vulns: include("high" => 0))
    expect(FleetCompliance.new.rows).to be_empty
    expect(FleetList.new.hosts.map(&:id)).to eq([ host.id ])
    expect(summary(host)).to have_attributes(vuln_high: 1, fleet_vulns_key: nil)
    host.retire!(actor: Audit::SYSTEM)
    expect(FleetList.new.hosts).to be_empty
    expect_consistent(host)
  end

  it "moves only the status sort key when liveness alone changes" do
    host, = enrolled_host
    record_heartbeat(host)
    findings!(host, "low")
    before = summary(host).attributes
    HostLiveness.where(host_id: host.id).update_all(liveness_status: "offline")
    expect(summary(host).attributes).to eq(before.merge("status_rank" => 2))
    expect_consistent(host)
  end

  it "recounts the queue in batches, refreshing open pages once, and does nothing when it is empty" do
    hosts = Array.new(3) { enrolled_host.first }
    hosts.each { |host| findings!(host, "high") }
    Advisory.update_all(severity: "critical")
    expect(described_class.queued).to eq(3)
    stub_const("HostComplianceSummary::BATCH_SIZE", 2)
    expect(FleetBroadcast).to receive(:refresh).once
    expect(ComplianceSummaryRecountJob.perform_now).to eq(3)
    hosts.each { |host| expect(summary(host)).to have_attributes(vuln_high: 0, vuln_critical: 1) }
    expect(ComplianceSummaryRecountJob.perform_now).to eq(0)
  end

  it "queues the recount when an advisory import commits" do
    expect { ActiveRecord::Base.transaction { ComplianceSummaryRecountJob.after_import } }.to have_enqueued_job(ComplianceSummaryRecountJob)
  end

  it "refuses TRUNCATE on the tables the counts come from" do
    %w[cis_results vulnerability_findings host_vulnerability_evaluations host_inventories].each do |table|
      expect { described_class.transaction(requires_new: true) { described_class.connection.execute("TRUNCATE #{table} CASCADE") } }
        .to raise_error(ActiveRecord::StatementInvalid, /#{table} is not truncated: the compliance summaries are built from it/)
    end
  end

  it "keeps a lowered name of any length, as lower() can lengthen it (ICU)" do
    expect(described_class.columns_hash["name_key"].sql_type).to eq("text")
    host = create(:host, name: "A" * 100)
    expect(summary(host).name_key).to eq("a" * 100)
  end

  it "rebuilds rows written wrong or missing, and its check names them without writing" do
    host, = enrolled_host
    other, = enrolled_host
    findings!(host, "high")
    described_class.where(host_id: host.id).update_all(vuln_high: 7, name_key: "wrong")
    described_class.where(host_id: other.id).delete_all
    expect(described_class.drift(batch_size: 1)).to contain_exactly(host.id, other.id)
    expect(described_class.where(host_id: host.id).pick(:vuln_high)).to eq(7)
    expect(described_class.exists?(other.id)).to be(false)

    Advisory.update_all(severity: "critical") # queued, then emptied by the rebuild
    expect(described_class.rebuild!(batch_size: 1)).to eq(2)
    expect(described_class.queued).to eq(0)
    expect(summary(host)).to have_attributes(vuln_critical: 1, name_key: host.name.downcase)
    expect(summary(other).status_rank).to eq(3)
    expect_consistent(host, other)
  end
end
