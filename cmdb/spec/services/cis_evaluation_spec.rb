require "rails_helper"

# Evaluating rules on hosts and storing results and result changes (P2-S06, FR-2.2).
RSpec.describe CisEvaluation do
  let(:host) { enrolled_host.first }
  let(:now) { Time.utc(2026, 11, 7, 12) }

  before do
    allow(CisEvaluationJob).to receive(:perform_later) # evaluation is run by hand here
    record_inventory(host) # Debian 13
  end

  def evaluate(hosts = [ host ], at: now, **options) = described_class.evaluate!(hosts.map(&:id), now: at, **options)

  def results(on = host) = CisResult.where(host: on).joins(:cis_rule).order("cis_rules.key").pluck("cis_rules.key", :result, :reason)

  it "stores one result per rule, naming the rule version and the snapshot, with the observed value" do
    rule, = define_cis_rules(cis_rule_hash)
    record_config(host)
    outcome = evaluate
    expect(outcome).to have_attributes(hosts: 1, results: 1, changes: 1)
    expect(CisResult.sole).to have_attributes(host:, cis_rule: rule, cis_rule_version: rule.current_version, config_snapshot: ConfigSnapshot.sole,
                                              result: "pass", observed: "no", reason: nil, evaluated_at: now, changed_at: now)
    expect(CisResultChange.sole).to have_attributes(from_result: nil, to_result: "pass", occurred_at: now, observed: "no")
  end

  it "evaluates the latest snapshot" do
    define_cis_rules(cis_rule_hash)
    record_config(host)
    travel(1.minute) { record_config(host, "sshd.permitrootlogin" => ok_fact("yes")) }
    evaluate
    expect(CisResult.sole).to have_attributes(result: "fail", observed: "yes", config_snapshot: ConfigSnapshot.chronological.last)
  end

  it "marks every rule not evaluated on a host with no config report, and a disabled rule on any host" do
    define_cis_rules(cis_rule_hash, cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }))
    other = enrolled_host.first
    record_inventory(other)
    record_config(other)
    CisRule.transaction { CisRule.find_by!(key: "ssh-max-auth-tries").disable!(actor: Audit::SYSTEM) }
    evaluate([ host, other ])
    expect(results(host)).to eq([ [ "ssh-max-auth-tries", "not_evaluated", CisEvaluation::DISABLED ], [ "ssh-root-login-off", "not_evaluated", CisEvaluation::NO_REPORT ] ])
    expect(results(other)).to eq([ [ "ssh-max-auth-tries", "not_evaluated", CisEvaluation::DISABLED ], [ "ssh-root-login-off", "pass", nil ] ])
    expect(CisResult.where(result: "not_evaluated").pluck(:cis_rule_version_id, :config_snapshot_id).uniq).to eq([ [ nil, nil ] ])
  end

  it "is not_readable when the host has not reported its operating system, and not_applicable on another distribution" do
    define_cis_rules(cis_rule_hash)
    bare = enrolled_host.first
    record_config(bare)
    elsewhere = enrolled_host.first
    record_inventory(elsewhere, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu 24.04" })
    record_config(elsewhere)
    evaluate([ bare, elsewhere ])
    expect(results(bare)).to eq([ [ "ssh-root-login-off", "not_readable", "The host has not reported its operating system." ] ])
    expect(results(elsewhere).first[1]).to eq("not_applicable")
  end

  it "writes a change only when the result changes, while keeping the current value and its time up to date" do
    define_cis_rules(cis_rule_hash(fact: "sshd.maxauthtries", condition: { "lte" => 4 }))
    record_config(host, "sshd.maxauthtries" => ok_fact(4))
    evaluate
    travel(1.minute) { record_config(host, "sshd.maxauthtries" => ok_fact(3)) }
    expect { evaluate(at: now + 1.hour) }.not_to change(CisResultChange, :count)
    expect(CisResult.sole).to have_attributes(result: "pass", observed: 3, evaluated_at: now + 1.hour, changed_at: now)
    expect { evaluate(at: now + 2.hours) }.not_to change { [ CisResultChange.count, CisResult.sole.changed_at ] }
  end

  it "evaluates only the rules asked for" do
    first, second = define_cis_rules(cis_rule_hash, cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }))
    record_config(host)
    evaluate(rule_ids: [ second.id ])
    expect(CisResult.pluck(:cis_rule_id)).to eq([ second.id ])
    expect(evaluate(rule_ids: [ first.id, second.id ])).to have_attributes(results: 2, changes: 1)
  end

  it "skips retired hosts, and does nothing when there are no rules to evaluate" do
    define_cis_rules(cis_rule_hash)
    record_config(host)
    host.retire!(actor: Audit::SYSTEM)
    expect(evaluate).to have_attributes(hosts: 0, results: 0, changes: 0)
    expect(evaluate([ enrolled_host.first ], rule_ids: [])).to have_attributes(hosts: 0, results: 0, changes: 0)
  end

  it "keeps results and changes when the snapshot they name is pruned, clearing only its id" do
    define_cis_rules(cis_rule_hash)
    record_config(host)
    evaluate
    snapshot = ConfigSnapshot.sole
    ConfigSnapshot.where(id: snapshot.id).delete_all
    expect([ CisResult.sole.config_snapshot_id, CisResultChange.sole.config_snapshot_id ]).to eq([ nil, nil ])
  end

  it "refuses a history row that is not a change (the database checks it)" do
    rule, = define_cis_rules(cis_rule_hash)
    expect { CisResultChange.create!(host:, cis_rule: rule, from_result: "pass", to_result: "pass", occurred_at: now) }.to raise_error(ActiveRecord::StatementInvalid, /is_a_change/)
  end
end
