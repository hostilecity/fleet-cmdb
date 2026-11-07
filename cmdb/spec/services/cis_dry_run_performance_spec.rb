require "rails_helper"

# P2-S14: a preview on a fleet of 50 hosts with a few hundred rules, every one evaluated, takes under 2 s and a
# fixed number of queries.
RSpec.describe "CisDryRun at fleet scale" do
  let(:hosts) { 50 }
  let(:rules) { 300 }
  let(:budget) { 2.0 } # docs/backlog/specs/p2-rule-dryrun.md

  def timed
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  end

  before do
    allow(CisEvaluationJob).to receive(:perform_later)
    define_cis_rules(*Array.new(rules) { |i| cis_rule_hash(key: "rule-#{i}", fact: "sshd.maxauthtries", condition: { "lte" => i % 7 }) })
    @ids = Array.new(hosts) do |h|
      host = enrolled_host(hostname: "vm-#{h}.example.lan").first
      record_inventory(host)
      record_config(host, "sshd.maxauthtries" => ok_fact(h % 7))
      host.id
    end
    CisEvaluation.evaluate!(@ids) # 15,000 current results
  end

  it "previews one rule on 50 hosts within the budget, in a fixed number of queries" do
    edited = cis_rule_hash(key: "rule-3", fact: "sshd.maxauthtries", condition: { "lte" => 4 })
    preview = nil
    queries = 0
    elapsed = timed { queries = count_queries { preview = CisDryRun.call(edited).preview } }
    puts "\n  P2-S14: previewed 1 rule on #{hosts} hosts (#{rules} rules) in #{(elapsed * 1000).round} ms, #{queries} queries" if ENV["SHOW_TIMINGS"]
    expect(CisResult.count).to eq(hosts * rules)
    expect(preview.counts).to have_attributes(hosts:, pass_to_fail: 0, fail_to_pass: 7) # hosts observing 4 now pass
    expect(elapsed).to be < budget
    expect(queries).to be <= 6
  end
end
