require "rails_helper"

# A host's compliance summary from its current CIS results (P2-S06, FR-2.2).
RSpec.describe CisCompliance do
  before { allow(CisEvaluationJob).to receive(:perform_later) }

  let(:host) { enrolled_host.first }

  it "counts each result, and every rule without a result for the host as not evaluated" do
    rules = define_cis_rules(
      cis_rule_hash,                                                                                          # pass
      cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 3 }),        # fail: 4
      cis_rule_hash(key: "sudoers-mode", fact: "file:/etc/sudoers", condition: { "mode_at_most" => "0440" }), # not readable
      cis_rule_hash(key: "ubuntu-only", applies_to: [ { "distribution" => "ubuntu" } ]),                        # not applicable
      cis_rule_hash(key: "later")                                                                             # no result yet
    )
    record_inventory(host)
    record_config(host)
    CisEvaluation.evaluate!([ host.id ], rule_ids: rules.first(4).map(&:id))
    summary = described_class.for_host(host.id)
    expect(summary).to have_attributes(passed: 1, failed: 1, not_readable: 1, not_applicable: 1, not_evaluated: 1, total: 5)
  end

  it "counts only the rules it read first, whatever is evaluated meanwhile (review of #110)" do
    define_cis_rules(cis_rule_hash)
    record_inventory(host)
    record_config(host)
    CisEvaluation.evaluate!([ host.id ])
    added = false
    allow(CisResult).to receive(:where).and_wrap_original do |original, *args, **kwargs|
      unless added # a rule imported and evaluated between the summary's two queries
        added = true
        define_cis_rules(cis_rule_hash(key: "later"))
        CisEvaluation.evaluate!([ host.id ])
      end
      original.call(*args, **kwargs)
    end
    expect(described_class.for_host(host.id)).to have_attributes(passed: 1, not_evaluated: 0, total: 1)
  end

  it "summarises many hosts at once, a host with no results as all not evaluated" do
    define_cis_rules(cis_rule_hash)
    other = enrolled_host.first
    record_inventory(host)
    record_config(host)
    CisEvaluation.evaluate!([ host.id ])
    summaries = described_class.for_hosts([ host.id, other.id ])
    expect(summaries.transform_values(&:to_h)).to eq(
      host.id => { passed: 1, failed: 0, not_applicable: 0, not_readable: 0, not_evaluated: 0 },
      other.id => { passed: 0, failed: 0, not_applicable: 0, not_readable: 0, not_evaluated: 1 }
    )
  end
end
