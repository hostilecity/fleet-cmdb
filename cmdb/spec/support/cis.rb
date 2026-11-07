# Helpers for CIS rule specs (P2-S04 to P2-S06).
module CisHelpers
  def cis_rule_hash(**overrides)
    { "key" => "ssh-root-login-off", "reference" => "CIS Debian 13 5.1.20", "title" => "SSH does not let root log in", "severity" => "high",
      "applies_to" => [ { "distribution" => "debian", "versions" => [ "13" ] } ], "fact" => "sshd.permitrootlogin",
      "condition" => { "eq" => "no" }, "remediation" => "Set PermitRootLogin to no." }.merge(overrides.transform_keys(&:to_s))
  end

  # Defines the rules directly, as an import does, and returns them.
  def define_cis_rules(*rules)
    CisRule.transaction { rules.each { |rule| CisRule.define!(CisRules::Definition.from_h(rule), actor: Audit::SYSTEM) } }
    CisRule.where(key: rules.map { |rule| rule["key"] }).order(:id).to_a
  end

  # Stores a config report for an enrolled host through ConfigRecorder, as the endpoint does. facts are merged
  # over the typical docs/api example; collected_at (the agent's clock) defaults to the example's.
  def record_config(host, facts = {}, collected_at = nil)
    example = ApiContract.example("config.request", "typical")
    payload = example.merge("report_id" => SecureRandom.uuid, "facts" => example["facts"].merge(facts))
    payload["collected_at"] = collected_at.utc.iso8601 if collected_at
    Host.transaction do
      ConfigRecorder.record!(host_id: host.id, credential_id: host.agent_credentials.active.pick(:id), report: AgentApi::ConfigReport.new(payload))
    end
  end

  def ok_fact(value) = { "state" => "ok", "value" => value, "reason" => nil }
end

RSpec.configure do |config|
  config.include CisHelpers
end
