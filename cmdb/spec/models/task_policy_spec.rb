require "rails_helper"

RSpec.describe TaskPolicy do
  it "allows a valid task of a type without server-side lists" do
    expect(described_class.refusal("refresh_reports", {})).to be_nil
    expect(described_class.refusal("apply_package_updates", {})).to be_nil
  end

  it "refuses unknown types and invalid parameters, with pointers into the request" do
    expect(described_class.refusal("reboot", {})).to eq(TaskPolicy::Refusal.new(reason: "unknown_type", errors: [ { "pointer" => "/type", "problem" => "is not a task type in the catalog" } ]))
    expect(described_class.refusal("refresh_reports", { "types" => [ "config" ] }))
      .to eq(TaskPolicy::Refusal.new(reason: "invalid_params", errors: [ { "pointer" => "/parameters/types", "problem" => "is not a parameter of refresh_reports" } ]))
  end

  it "refuses every restart while the server allowlist is empty (DEC-15)" do
    expect(described_class.restart_allowlist).to eq([])
    expect(described_class.refusal("restart_service", { "service" => "nginx.service" }).reason).to eq("not_allowed_on_server")
  end

  it "always refuses protected services, even when listed (DEC-15)" do
    protected = %w[fleet-agent.service ssh.service sshd.service SSH.service systemd-journald.service systemd-networkd.service
                   networking.service NetworkManager.service ifup@eth0.service dbus.service dbus-broker.service
                   sshd@blue.service ssh@1.service fleet-agent-rollback.service fleet-agent@x.service
                   NetworkManager-dispatcher.service dbus@user.service]
    allow(described_class).to receive(:restart_allowlist).and_return(protected + %w[nginx.service])
    protected.each { |service| expect(described_class.refusal("restart_service", { "service" => service })&.reason).to eq("protected_service"), service }
    expect(described_class.refusal("restart_service", { "service" => "nginx.service" })).to be_nil
    expect(described_class.protected_service?("systemd-resolved.service")).to be(true)
    expect(described_class.protected_service?("my-systemd-app.service")).to be(false)
    expect(described_class.protected_service?("fleet-agentx.service")).to be(true) # a prefix, as on the agent
    expect(described_class.protected_service?("sshguard.service")).to be(false)
  end
end
