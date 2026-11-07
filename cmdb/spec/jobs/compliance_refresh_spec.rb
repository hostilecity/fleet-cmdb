require "rails_helper"

# Live refresh of the compliance counts (P2-D05): CIS evaluation and vulnerability matching broadcast one fleet refresh
# per run, after every host's transaction has committed, and only when what the compliance view and fleet list show
# changed. A rules file import is one run.
RSpec.describe "Compliance live refresh", type: :job do
  include ActiveJob::TestHelper

  def refreshes = enqueued_jobs.select { |job| job["job_class"] == "FleetBroadcastJob" }

  def refreshed_ids = refreshes.map { |job| job["arguments"].first }

  def evaluation_jobs = enqueued_jobs.select { |job| job["job_class"] == "CisEvaluationJob" }

  def configured_hosts(count)
    Array.new(count) { enrolled_host.first.tap { |host| record_inventory(host) && record_config(host) } }
  end

  describe "CIS evaluation" do
    let!(:hosts) { configured_hosts(4) }

    before { clear_enqueued_jobs }

    it "evaluates every rule a rules file import changed in one job, so the import is one run" do
      CisRule.transaction { define_cis_rules(*%w[a b c].map { |k| cis_rule_hash(key: "rule-#{k}") }) }
      expect(evaluation_jobs.size).to eq(1)
      expect(evaluation_jobs.first["arguments"].first["rule_ids"]).to match_array(CisRule.ids)
    end

    it "evaluates nothing for a rolled-back change, and does not carry its rules into the next one" do
      CisRule.transaction do
        define_cis_rules(cis_rule_hash(key: "rolled-back"))
        raise ActiveRecord::Rollback
      end
      expect(evaluation_jobs).to be_empty
      kept, = define_cis_rules(cis_rule_hash(key: "kept"))
      expect(evaluation_jobs.map { |job| job["arguments"].first["rule_ids"] }).to eq([ [ kept.id ] ])
    end

    it "broadcasts once for a fleet-wide run that changed results on many hosts, and nothing for a run that changed none" do
      define_cis_rules(cis_rule_hash(key: "root-login"), cis_rule_hash(key: "root-login-2", condition: { "ne" => "no" }))
      clear_enqueued_jobs
      CisEvaluationJob.perform_now(rule_ids: CisRule.ids)
      expect(refreshes.size).to eq(1)
      expect(refreshed_ids.first).to match_array(hosts.map(&:id))

      clear_enqueued_jobs
      CisEvaluationJob.perform_now(rule_ids: CisRule.ids)
      CisEvaluationJob.perform_now(host_ids: hosts.map(&:id))
      expect(refreshes).to be_empty
    end

    it "broadcasts for one host whose result changed after a new config report, and for a failure counted under a new severity" do
      rule, = define_cis_rules(cis_rule_hash(condition: { "eq" => "yes" })) # the typical config says no: every host fails
      CisEvaluationJob.perform_now(rule_ids: [ rule.id ])
      clear_enqueued_jobs
      record_config(hosts.first, "sshd.permitrootlogin" => ok_fact("yes"))
      CisEvaluationJob.perform_now(host_ids: [ hosts.first.id ])
      expect(refreshed_ids).to eq([ [ hosts.first.id ] ])

      clear_enqueued_jobs
      CisRule.transaction { rule.revise!(CisRules::Definition.from_h(cis_rule_hash(condition: { "eq" => "yes" }, severity: "critical")), actor: Audit::SYSTEM) }
      CisEvaluationJob.perform_now(rule_ids: [ rule.id ]) # results stay fail on three hosts, now under a critical version
      expect(refreshed_ids).to eq([ hosts.drop(1).map(&:id) ])
    end
  end

  describe "vulnerability matching" do
    it "broadcasts once for a run over many hosts, and nothing when a run changes nothing" do
      hosts = Array.new(3) { debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ] ]) }
      clear_enqueued_jobs
      VulnerabilityMatchJob.perform_now(host_ids: hosts.map(&:id)) # first evaluation: no advisory data
      expect(refreshed_ids).to eq([ hosts.map(&:id) ])

      clear_enqueued_jobs
      VulnerabilityMatchJob.perform_now(host_ids: hosts.map(&:id))
      expect(refreshes).to be_empty
    end

    it "broadcasts once after an import that changed advisories, and once when matching opens findings on many hosts" do
      hosts = Array.new(3) { debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ] ]) }
      VulnerabilityMatchJob.perform_now(host_ids: hosts.map(&:id))
      clear_enqueued_jobs
      import_advisories(osv_record(id: "DSA-1-1", package: "curl", fixed: "8.14.1-2"))
      perform_enqueued_jobs(only: VulnerabilityMatchJob) # the import's run
      expect(VulnerabilityFinding.active.count).to eq(3)
      expect(refreshes.size).to eq(1)

      clear_enqueued_jobs
      VulnerabilityMatchJob.perform_now(packages: { "Debian:13" => [ "curl" ] }) # the same advisories again: severities may have moved
      expect(refreshes.size).to eq(1)
    end

    it "sends nothing after a run for an import that named no package and changed no host" do
      debian_host(packages: [ [ "vim", "2:9.1-1", "vim" ] ]).then { |host| VulnerabilityMatchJob.perform_now(host_ids: [ host.id ]) }
      clear_enqueued_jobs
      VulnerabilityMatchJob.perform_now(packages: { "Debian:13" => [] })
      expect(refreshes).to be_empty
    end
  end

  it "refreshes with no page subscribed without failing" do
    ActionCable.server.pubsub.clear
    host = configured_hosts(1).first
    define_cis_rules(cis_rule_hash)
    expect { perform_enqueued_jobs { CisEvaluationJob.perform_now(host_ids: [ host.id ]) } }.not_to raise_error
    expect(ActionCable.server.pubsub.broadcasts(FleetBroadcast::STREAM).size).to eq(1)
  end
end
