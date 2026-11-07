require "rails_helper"

# Why a host's CIS-aligned results changed (P2-D02): leaving "not evaluated" (review of #118).
RSpec.describe CisResultHistory do
  let(:start) { Time.utc(2026, 11, 6, 9) }
  let(:host) { enrolled_host.first }

  before do
    allow(CisEvaluationJob).to receive(:perform_later)
    record_inventory(host)
    define_cis_rules(cis_rule_hash)
  end

  def evaluate(at) = CisEvaluation.evaluate!([ host.id ], now: at)

  def latest_cause = described_class.new(host.id).latest(1).sole.cause

  it "names the host's first config report after none as the report, by the reason it was not evaluated" do
    evaluate(start) # no report yet
    travel_to(start + 1.hour) { record_config(host) }
    evaluate(start + 2.hours)
    expect(latest_cause).to eq(:report)
  end

  it "falls back to the times when the change before was pruned" do
    rule = CisRule.sole
    travel_to(start) { record_config(host) }
    evaluate(start)
    CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) }
    evaluate(start + 1.hour)
    CisRule.transaction { rule.enable!(actor: Audit::SYSTEM) }
    evaluate(start + 2.hours)
    CisResultChange.where(occurred_at: ..start + 1.hour).delete_all
    expect(latest_cause).to eq(:report) # with nothing before it, the newest snapshot is all there is to go on

    travel_to(start + 3.hours) { record_config(host, "sshd.maxauthtries" => ok_fact(9)) }
    CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) }
    evaluate(start + 4.hours)
    CisRule.transaction { rule.enable!(actor: Audit::SYSTEM) }
    evaluate(start + 5.hours)
    CisResultChange.where(occurred_at: start + 4.hours).update_all(reason: nil) # a row whose reason was not kept
    expect(latest_cause).to eq(:rule_enabled)
  end
end
