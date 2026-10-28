# Helpers for onboarding specs (P1-ONBOARD).
module OnboardingHelpers
  def onboarding_facts(**overrides)
    { "schema_version" => 1, "agent_version" => "0.1.0", "hostname" => "vm-01.example.lan",
      "machine_id" => "0123456789abcdef0123456789abcdef",
      "os" => { "id" => "debian", "version_id" => "13", "pretty_name" => "Debian GNU/Linux 13 (trixie)" } }.merge(overrides.transform_keys(&:to_s))
  end

  # Starts a request the way the endpoint does. Returns OnboardingRequest::Started.
  def start_onboarding(client_ip: "192.0.2.10", **facts)
    Onboarding::Start.call(facts: onboarding_facts(**facts), client_ip:)
  end

  def collect_onboarding(device_code)
    Onboarding::Collect.call(device_code:, agent_version: "0.1.0", schema_version: 1)
  end
end

RSpec.configure do |config|
  config.include OnboardingHelpers
end
