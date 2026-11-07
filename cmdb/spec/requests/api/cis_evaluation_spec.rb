require "rails_helper"

# CIS rule evaluation end to end through the agent API, rule imports, and the background jobs (P2-S06, FR-2.2,
# AC-2.1, AC-2.2, AC-2.5).
RSpec.describe "CIS rule evaluation from config reports", type: :request do
  include ActiveJob::TestHelper

  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }
  let(:example) { ApiContract.example("config.request", "typical") }

  before { record_inventory(host) } # Debian 13

  def rule(**overrides)
    { "key" => "ssh-root-login-off", "reference" => "CIS Debian 13 5.1.20", "title" => "SSH does not let root log in", "severity" => "high",
      "applies_to" => [ { "distribution" => "debian", "versions" => [ "13" ] } ], "fact" => "sshd.permitrootlogin",
      "condition" => { "eq" => "no" }, "remediation" => "Set PermitRootLogin to no." }.merge(overrides.transform_keys(&:to_s))
  end

  let(:sudoers) { rule(key: "sudoers-mode", fact: "file:/etc/sudoers", condition: { "mode_at_most" => "0440" }, title: "sudoers is not writable") }

  def import(*rules)
    perform_enqueued_jobs { expect(CisRules::Import.call({ "format_version" => 1, "rules" => rules }.to_yaml, actor: Audit::SYSTEM)).to be_ok }
  end

  def send_config(changes = {})
    perform_enqueued_jobs { post_api("/api/v1/reports/config", example.merge("report_id" => SecureRandom.uuid, "facts" => example["facts"].merge(changes)), credential) }
    expect(response).to have_http_status(:ok)
  end

  def root_login(value) = { "sshd.permitrootlogin" => { "state" => "ok", "value" => value, "reason" => nil } }

  def result(key) = CisResult.joins(:cis_rule).find_by!(host:, cis_rules: { key: })

  def changes(key) = CisResultChange.joins(:cis_rule).where(host:, cis_rules: { key: }).chronological.pluck(:from_result, :to_result)

  it "flips a rule between pass and fail when an SSH setting changes between snapshots, and records each change (AC-2.1)" do
    import(rule)
    send_config
    expect(result("ssh-root-login-off")).to have_attributes(result: "pass", observed: "no", config_snapshot: ConfigSnapshot.where(host:).sole)

    send_config(root_login("yes"))
    second = ConfigSnapshot.where(host:).chronological.last
    expect(result("ssh-root-login-off")).to have_attributes(result: "fail", observed: "yes", config_snapshot: second)
    send_config(root_login("no"))
    expect(result("ssh-root-login-off").result).to eq("pass")

    # not_evaluated first: the rule was imported before the host's first config report.
    expect(changes("ssh-root-login-off")).to eq([ [ nil, "not_evaluated" ], %w[not_evaluated pass], %w[pass fail], %w[fail pass] ])
    flip = CisResultChange.chronological.third
    expect(flip).to have_attributes(config_snapshot_id: second.id, observed: "yes", cis_rule_version: CisRule.sole.current_version)
  end

  it "changes results when a rule's expected value is edited, with no agent involved (AC-2.2)" do
    import(rule)
    send_config
    expect(result("ssh-root-login-off").result).to eq("pass")

    expect { import(rule(condition: { "eq" => "prohibit-password" })) }.not_to change(ConfigSnapshot, :count)
    current = result("ssh-root-login-off")
    expect(current).to have_attributes(result: "fail", observed: "no", cis_rule_version: CisRule.sole.current_version)
    expect(current.cis_rule_version.version).to eq(2)
    expect(changes("ssh-root-login-off").last).to eq(%w[pass fail])
  end

  it "makes a result not_readable, with the agent's reason, when its fact is unreadable (AC-2.5)" do
    import(sudoers)
    send_config
    expect(result("sudoers-mode")).to have_attributes(result: "not_readable", reason: "Permission denied reading /etc/sudoers.", observed: nil)
  end

  it "shows a disabled rule as not evaluated, and evaluates it again when it is enabled" do
    import(rule, sudoers)
    send_config
    import(rule.merge("enabled" => false), sudoers)
    expect(result("ssh-root-login-off")).to have_attributes(result: "not_evaluated", reason: CisEvaluation::DISABLED, cis_rule_version: nil)
    import(rule.merge("enabled" => true), sudoers)
    expect(result("ssh-root-login-off").result).to eq("pass")
    expect(CisCompliance.for_host(host.id)).to have_attributes(passed: 1, failed: 0, not_readable: 1, not_evaluated: 0)
  end

  it "evaluates a rule imported after the host's report, from the snapshot it already has" do
    send_config
    import(rule)
    expect(result("ssh-root-login-off").result).to eq("pass")
  end

  it "writes no history when evaluation runs again with nothing changed" do
    import(rule, sudoers)
    send_config
    expect do
      perform_enqueued_jobs do
        CisEvaluationJob.perform_later(host_ids: [ host.id ])
        CisEvaluationJob.perform_later(rule_ids: CisRule.ids)
      end
      send_config # the same facts: no snapshot, so no evaluation either
      import(rule, sudoers) # the same rules: no new version
    end.not_to change(CisResultChange, :count)
  end
end
