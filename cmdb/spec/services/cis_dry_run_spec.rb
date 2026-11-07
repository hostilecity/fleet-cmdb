require "rails_helper"

# Dry run of an unsaved rule definition for the edit preview (P2-S14, FR-2.2, AC-2.2).
RSpec.describe CisDryRun do
  let(:rule) { cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }, title: "SSH allows at most 4 tries") }
  let(:edited) { rule.merge("condition" => { "in" => [ 3, 6 ] }) }
  let(:unreadable) { { "state" => "unreadable", "value" => nil, "reason" => "Permission denied reading /etc/ssh/sshd_config." } }

  let(:enqueued) { [] }

  # Evaluation is run by hand here; what would have been enqueued is kept.
  before { allow(CisEvaluationJob).to receive(:perform_later) { |**arguments| enqueued << arguments } }

  def host(name, os: :debian, tries: nil, fact: nil)
    host = enrolled_host(name:, hostname: "#{name}.example.lan").first
    record_inventory(host) if os == :debian
    record_inventory(host, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu 24.04" }) if os == :ubuntu
    record_config(host, "sshd.maxauthtries" => fact || ok_fact(tries)) if tries || fact
    host
  end

  def evaluate_all(rule_ids: nil) = CisEvaluation.evaluate!(Host.in_fleet.pluck(:id), rule_ids:)

  # A fleet of mixed results under `rule`, evaluated, then one host's snapshot changed without evaluating it again.
  def mixed_fleet
    @hosts = {
      passes: host("web-01", tries: 4),        # pass now, fail under `edited`
      stays: host("web-02", tries: 3),         # pass either way
      fails: host("db-01", tries: 6),          # fail now, pass under `edited`
      unreadable: host("db-02", fact: unreadable), # not_readable either way
      ubuntu: host("ubuntu-01", os: :ubuntu, tries: 4), # not applicable
      silent: host("new-01"),                  # no config report
      no_os: host("bare-01", os: nil, tries: 4), # not_readable: no operating system reported
      stale: host("app-01", tries: 3)          # pass now; its latest snapshot (not yet evaluated) is unreadable
    }
    host("old-01", tries: 4).retire!(actor: Audit::SYSTEM)
    define_cis_rules(rule)
    evaluate_all
    travel(1.minute) { record_config(@hosts[:stale], "sshd.maxauthtries" => unreadable) }
  end

  def listed(preview) = preview.changes.to_h { |change| [ change.host_name, [ change.from, change.to ] ] }

  # What saving the definition records, as the dashboard and an import save it: CisRule.define! (and the flag, as
  # CisRules::Import sets it), then the evaluation jobs that enqueues, if any. Returns the changes written, by host name.
  def save(definition)
    before = CisResultChange.maximum(:id) || 0
    jobs = enqueued.size
    CisRule.transaction do
      CisRule.define!(CisRules::Definition.from_h(definition), actor: Audit::SYSTEM, enabled: definition["enabled"] != false)
      stored = CisRule.find_by!(key: definition["key"])
      definition["enabled"] ? stored.enable!(actor: Audit::SYSTEM) : stored.disable!(actor: Audit::SYSTEM) unless definition["enabled"].nil?
    end
    enqueued.drop(jobs).each { |arguments| CisEvaluationJob.new.perform(**arguments) }
    CisResultChange.where("cis_result_changes.id > ?", before).joins(:host).order(:id)
                   .pluck("hosts.name", :from_result, :to_result, :observed, :reason).to_h { |name, *rest| [ name, rest ] }
  end

  # The dry run and saving agree: every listed change is a recorded change with the same from, to, observed value,
  # and reason, and every other recorded change is a host the preview counted as not applicable or without a report.
  def expect_same_as_saving(definition)
    preview = described_class.call(definition).preview
    saved = save(definition)
    shown = preview.changes.to_h { |change| [ change.host_name, [ change.from, change.to, change.observed, change.reason ] ] }
    expect(saved.slice(*shown.keys)).to eq(shown)
    unlisted = saved.except(*shown.keys)
    expect(unlisted.size).to eq(preview.counts.unlisted_changes)
    expect(unlisted.values.map(&:second).uniq - %w[not_applicable not_evaluated]).to eq([])
    preview
  end

  it "lists the hosts whose result would change, with the current result, the result under the definition, and the observed value" do
    mixed_fleet
    result = described_class.call(edited)
    expect(result).to be_ok
    preview = result.preview
    expect(preview).to have_attributes(key: "ssh-max-auth-tries", current_version: 1, next_version: 2, currently_enabled: true, enabled: true)
    expect(preview).not_to be_new_rule
    expect(preview.changes.map(&:host_name)).to eq(%w[app-01 db-01 web-01]) # sorted by name
    expect(preview.changes.find { |change| change.host_name == "web-01" })
      .to have_attributes(host_id: @hosts[:passes].id, hostname: "web-01.example.lan", from: "pass", to: "fail", observed: 4, current_observed: 4, reason: nil)
    expect(preview.changes.find { |change| change.host_name == "db-01" }).to have_attributes(from: "fail", to: "pass", observed: 6, current_observed: 6)
    expect(preview.changes.find { |change| change.host_name == "app-01" })
      .to have_attributes(from: "pass", to: "not_readable", observed: nil, current_observed: 3, reason: unreadable["reason"])
    expect(preview.counts).to have_attributes(hosts: 8, changed: 3, pass_to_fail: 1, fail_to_pass: 1, other_changes: 1, unchanged: 3,
                                              not_applicable: 1, no_report: 1, unlisted_changes: 0)
  end

  describe "reporting exactly the changes that saving the same definition produces" do
    before { mixed_fleet }

    it "for an edited condition" do
      expect(expect_same_as_saving(edited).counts.changed).to eq(3)
    end

    it "for applies_to narrowed so that hosts that pass now would no longer be evaluated" do
      narrowed = rule.merge("applies_to" => [ { "distribution" => "debian", "versions" => [ "12" ] } ])
      preview = expect_same_as_saving(narrowed)
      # Every Debian 13 host would be not applicable, listed nowhere but counted in unlisted_changes; bare-01 has no
      # os, so it stays not_readable.
      expect(preview.counts).to have_attributes(changed: 0, unchanged: 1, not_applicable: 6, no_report: 1, unlisted_changes: 5)
      expect(listed(preview)).to eq({})
    end

    it "for a new rule, whose current result is none on every host" do
      preview = expect_same_as_saving(cis_rule_hash) # ssh-root-login-off; the typical report has it as no
      expect(preview).to be_new_rule
      expect(preview).to have_attributes(rule_id: nil, current_version: nil, next_version: 1, currently_enabled: nil, enabled: true)
      expect(preview.changes.map(&:from).uniq).to eq([ nil ])
      expect(preview.counts).to have_attributes(hosts: 8, changed: 6, not_applicable: 1, no_report: 1, unlisted_changes: 2, unchanged: 0)
    end

    it "for a rule disabled by the definition, and enabled again" do
      preview = expect_same_as_saving(rule.merge("enabled" => false))
      expect(preview).to have_attributes(next_version: nil, currently_enabled: true, enabled: false)
      expect(preview.changes.map(&:to).uniq).to eq([ "not_evaluated" ])
      expect(preview.changes.map(&:reason).uniq).to eq([ CisEvaluation::DISABLED ])
      expect(preview.counts).to have_attributes(changed: 7, no_report: 1) # a disabled rule is not evaluated, so not applicable either
      expect(expect_same_as_saving(edited.merge("enabled" => true)).counts).to have_attributes(changed: 6, not_applicable: 1, unlisted_changes: 1)
    end

    it "for a disabled rule edited without enabling it, which stays not evaluated" do
      save(rule.merge("enabled" => false))
      preview = expect_same_as_saving(edited)
      expect(preview).to have_attributes(next_version: 2, currently_enabled: false, enabled: false)
      expect(preview.counts).to have_attributes(changed: 0, unchanged: 7)
    end

    it "for the current definition unchanged, which saving does not evaluate again" do
      preview = expect_same_as_saving(rule)
      expect(preview).to be_saves_nothing
      expect(preview).to have_attributes(next_version: nil, changes: [])
      expect(preview.counts).to have_attributes(changed: 0, unlisted_changes: 0, unchanged: 6) # app-01 too, although its snapshot changed
    end
  end

  it "counts a host with no config report and a host the rule does not apply to, and never lists them" do
    mixed_fleet
    preview = described_class.call(edited).preview
    expect(preview.changes.map(&:host_id)).not_to include(@hosts[:silent].id, @hosts[:ubuntu].id)
    expect(preview.counts).to have_attributes(not_applicable: 1, no_report: 1)

    new_rule = described_class.call(cis_rule_hash).preview # every host would change, from none
    expect(new_rule.changes.map(&:host_id)).not_to include(@hosts[:silent].id, @hosts[:ubuntu].id)
    expect(new_rule.counts).to have_attributes(not_applicable: 1, no_report: 1, unlisted_changes: 2)
  end

  it "leaves every table unchanged and enqueues no job" do
    mixed_fleet
    tables = ActiveRecord::Base.connection.tables - %w[schema_migrations ar_internal_metadata]
    expect(tables).to include("cis_rules", "cis_rule_versions", "cis_results", "cis_result_changes", "audit_entries")
    rows = -> { tables.to_h { |table| [ table, ActiveRecord::Base.connection.select_value("SELECT count(*) FROM #{ActiveRecord::Base.connection.quote_table_name(table)}") ] } }
    contents = -> { [ CisRule.order(:id).map(&:attributes), CisResult.order(:id).map(&:attributes), CisRuleVersion.order(:id).map(&:attributes) ] }
    before_rows = rows.call
    before_contents = contents.call
    jobs = SolidQueue::Job.count
    evaluations = enqueued.size

    expect do
      expect(described_class.call(edited)).to be_ok
      expect(described_class.call(cis_rule_hash)).to be_ok
      expect(described_class.call(rule.merge("enabled" => false))).to be_ok
    end.not_to have_enqueued_job
    expect(enqueued.size).to eq(evaluations)
    expect(rows.call).to eq(before_rows)
    expect(contents.call).to eq(before_contents)
    expect(SolidQueue::Job.count).to eq(jobs)
  end

  it "takes a CisRules::Definition, keeping the rule's flag" do
    mixed_fleet
    preview = described_class.call(CisRules::Definition.from_h(edited)).preview
    expect(preview).to have_attributes(next_version: 2, enabled: true)
    expect(preview.counts.changed).to eq(3)
  end

  describe "an invalid definition" do
    it "returns every problem with a JSON Pointer into the rule, and no preview" do
      result = described_class.call(rule.merge("severity" => "urgent", "fact" => "nope.fact"))
      expect(result).not_to be_ok
      expect(result.preview).to be_nil
      expect(result.errors.map(&:pointer)).to eq([ "/severity" ])
      expect(result.errors.first.message).to start_with("is not one of")

      expect(described_class.call(rule.merge("fact" => "nope.fact")).errors.map(&:to_s)).to eq([ "/fact: nope.fact is not in the fact manifest" ])
      expect(described_class.call(rule.merge("condition" => { "all" => [ { "eq" => "4" } ] })).errors.map(&:to_s))
        .to eq([ "/condition/all/0: eq needs an integer" ])
      expect(described_class.call(rule.except("reference")).errors.map(&:pointer)).to eq([ "/" ])
      expect(described_class.call(rule.merge("title" => "a\0b")).errors.map(&:to_s)).to eq([ "/title: contains a NUL character" ])
      expect(described_class.call("not a rule").errors.map(&:pointer)).to eq([ "/" ])
    end

    it "reads nothing from the database" do
      expect(count_queries { described_class.call(rule.merge("fact" => "nope.fact")) }).to eq(0)
    end
  end

  it "runs in a fixed number of queries whatever the size of the fleet" do
    define_cis_rules(rule)
    small = [ host("vm-01", tries: 4) ]
    evaluate_all
    few = count_queries { described_class.call(edited) }
    small += Array.new(10) { |i| host("vm-#{i + 2}", tries: 3 + (i % 4)) }
    host("vm-silent")
    evaluate_all
    many = 0
    preview = nil
    many = count_queries { preview = described_class.call(edited).preview }
    expect(preview.counts.hosts).to eq(small.size + 1)
    expect(many).to eq(few)
    expect(many).to be <= 6
  end
end
