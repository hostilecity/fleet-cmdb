require "rails_helper"

# The dashboard's import preview (P2-D06): what a rules file would do, worked out from one committed state of the
# rules without writing anything, and an import that applies only to that state (Import's expected_state, under the
# rules' write lock). Runs outside the test transaction, so the read-only transaction and the lock are real.
RSpec.describe CisRules::ImportPlan do
  self.use_transactional_tests = false

  before { allow(CisEvaluationJob).to receive(:perform_later) }

  after do
    CisRule.update_all(current_version_id: nil)
    CisRuleVersion.delete_all
    CisRule.delete_all
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # audit entries are protected
    AuditEntry.where(target_type: "CisRule").delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  def file(*rules) = JSON.generate({ "format_version" => 1, "rules" => rules })

  it "plans in one read-only transaction, writes nothing, and its digest lets the import refuse a changed state" do
    define_cis_rules(cis_rule_hash)
    text = file(cis_rule_hash(condition: { "eq" => "without-password" }))

    sql = []
    plan = ActiveSupport::Notifications.subscribed(->(*, payload) { sql << payload[:sql] }, "sql.active_record") { described_class.call(text).plan }
    expect(sql).to include(a_string_matching(/\ABEGIN ISOLATION LEVEL REPEATABLE READ/), "SET TRANSACTION READ ONLY")
    expect(sql.grep(/\A\s*(INSERT|UPDATE|DELETE)/i)).to eq([])
    expect(plan.changed.map(&:key)).to eq([ "ssh-root-login-off" ])
    expect(plan.state_digest).to eq(CisRule.state_digest)

    CisRule.transaction { CisRule.find_by!(key: "ssh-root-login-off").disable!(actor: Audit::SYSTEM) }
    expect { CisRules::Import.call(text, actor: Audit::SYSTEM, expected_state: plan.state_digest) }.to raise_error(CisRules::Import::Stale)
    expect(CisRuleVersion.count).to eq(1)

    result = CisRules::Import.call(text, actor: Audit::SYSTEM, expected_state: CisRule.state_digest)
    expect(result.versioned).to eq([ "ssh-root-login-off" ])
  end

  it "returns the file's problems and no plan for an invalid file" do
    result = described_class.call(file(cis_rule_hash(fact: "nope.fact")))
    expect(result).to have_attributes(ok?: false, plan: nil)
    expect(result.errors.map(&:to_s)).to eq([ "/rules/0/fact: nope.fact is not in the fact manifest" ])
  end
end
