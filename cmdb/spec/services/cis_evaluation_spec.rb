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

  it "keeps results and changes when the snapshot they name is no longer kept: the id stays, and names no snapshot (ADR 0027)" do
    define_cis_rules(cis_rule_hash)
    record_config(host)
    evaluate
    snapshot = ConfigSnapshot.sole
    ConfigSnapshot.where(id: snapshot.id).delete_all
    expect([ CisResult.sole.config_snapshot_id, CisResultChange.sole.config_snapshot_id ]).to eq([ snapshot.id, snapshot.id ])
    expect([ CisResult.sole.config_snapshot, CisResultChange.sole.config_snapshot ]).to eq([ nil, nil ])
  end

  describe "reading everything once the host is locked (review of #110)" do
    # Runs `change` the first time a host row is locked, as if it happened while the run waited for the lock.
    def when_locked(&change)
      done = false
      allow(Host).to receive(:lock).and_wrap_original do |original, *args|
        change.call unless done
        done = true
        original.call(*args)
      end
    end

    it "evaluates the rule as it is when the host is locked, not as it was when the run started, even with the query cache on" do
      rule, = define_cis_rules(cis_rule_hash)
      record_config(host)
      when_locked { define_cis_rules(cis_rule_hash(condition: { "eq" => "yes" })) }
      ActiveRecord::Base.cache { evaluate(rule_ids: [ rule.id ]) }
      expect(CisResult.sole).to have_attributes(result: "fail", cis_rule_version: rule.reload.current_version)
      expect(CisResult.sole.cis_rule_version.version).to eq(2)
    end

    it "sees a rule disabled while it waited" do
      rule, = define_cis_rules(cis_rule_hash)
      record_config(host)
      when_locked { CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) } }
      evaluate
      expect(CisResult.sole).to have_attributes(result: "not_evaluated", reason: CisEvaluation::DISABLED)
    end

    it "dates each chunk's results when its locks are taken, unless a time is given (#197)" do
      stub_const("CisEvaluation::LOCK_CHUNK", 2)
      define_cis_rules(cis_rule_hash)
      hosts = [ host, *Array.new(2) { enrolled_host.first } ]
      hosts.each { |h| record_inventory(h) && record_config(h) }
      start = Time.current.change(usec: 0)
      travel_to(start)
      allow(Host).to receive(:lock).and_wrap_original do |original, *args|
        travel(1.minute) # each chunk waits a minute for its locks
        original.call(*args)
      end
      described_class.evaluate!(hosts.map(&:id))
      expect(CisResult.order(:host_id).pluck(:evaluated_at)).to eq([ start + 1.minute, start + 1.minute, start + 2.minutes ])
      expect(CisResultChange.order(:host_id).pluck(:occurred_at)).to eq([ start + 1.minute, start + 1.minute, start + 2.minutes ])
    end

    it "locks a chunk's hosts in id order, in one statement, before reading the rules (#197)" do
      define_cis_rules(cis_rule_hash)
      hosts = [ host, enrolled_host.first ]
      hosts.each { |h| record_config(h) }
      statements = []
      subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| statements << payload[:sql] }
      described_class.evaluate!(hosts.map(&:id).reverse)
      ActiveSupport::Notifications.unsubscribe(subscriber)
      locks = statements.grep(/FOR UPDATE/)
      expect(locks.size).to eq(1)
      expect(locks.sole).to match(/ORDER BY "hosts"."id" ASC/)
      expect(statements.index(locks.sole)).to be < statements.index { |sql| sql.include?(%(SELECT "cis_rules".*)) } # the count before only sizes chunks
    end
  end

  it "sizes chunks by their work, then by how long each held its locks (review of #204)" do
    stub_const("CisEvaluation::EVALUATIONS_PER_CHUNK", 4)
    rules = define_cis_rules(cis_rule_hash, cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }))
    hosts = [ host, *Array.new(4) { enrolled_host.first.tap { |h| record_inventory(h) } } ]
    locks = lambda do |**options|
      sizes = []
      subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") do |*, payload|
        sizes << payload[:type_casted_binds].count { |value| value.is_a?(Integer) } if payload[:sql].include?("FOR UPDATE") # the host ids
      end
      described_class.evaluate!(hosts.map(&:id), **options)
      ActiveSupport::Notifications.unsubscribe(subscriber)
      sizes
    end
    expect(locks.call).to eq([ 2, 2, 1 ]) # two rules: 4 evaluations are 2 hosts
    expect(locks.call(rule_ids: [ rules.first.id ])).to eq([ 4, 1 ]) # one rule: 4 hosts
    stub_const("CisEvaluation::LOCK_TARGET", 0.000_001) # every chunk takes far longer than its target
    expect(locks.call(rule_ids: [ rules.first.id ])).to eq([ 4, 1 ])
    expect(locks.call).to eq([ 2, 1, 1, 1 ])
  end

  it "reads facts only on hosts where an enabled rule applies, and only the facts the rules name (#197)" do
    rule, = define_cis_rules(cis_rule_hash)
    elsewhere = enrolled_host.first
    record_inventory(elsewhere, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu 24.04" })
    [ host, elsewhere ].each { |h| record_config(h) }
    reads = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| reads << [ payload[:sql], payload[:type_casted_binds] ] if payload[:sql].include?("jsonb_each") }
    evaluate([ host, elsewhere ])
    CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) }
    evaluate([ host, elsewhere ])
    ActiveSupport::Notifications.unsubscribe(subscriber)
    expect(reads.size).to eq(1) # the first run, for the Debian host only; the disabled rule needs no facts
    sql, binds = reads.sole
    expect(sql).to include("IN ('sshd.permitrootlogin')")
    expect(binds).to eq([ ConfigSnapshot.find_by!(host:).id ])
    expect(results(elsewhere)).to eq([ [ "ssh-root-login-off", "not_evaluated", CisEvaluation::DISABLED ] ])
  end

  it "refuses a history row that is not a change (the database checks it)" do
    rule, = define_cis_rules(cis_rule_hash)
    expect { CisResultChange.create!(host:, cis_rule: rule, from_result: "pass", to_result: "pass", occurred_at: now) }.to raise_error(ActiveRecord::StatementInvalid, /is_a_change/)
  end
end
