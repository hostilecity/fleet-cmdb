require "rails_helper"

# The intervals the server asks agents to use (directives.intervals, P1-UPDATES, ADR 0019): audited settings.
RSpec.describe Setting, ".update_agent_intervals!" do
  let(:operator) { create(:operator) }

  it "sends nothing until an interval is set" do
    expect(described_class.agent_intervals).to eq({})
    expect(described_class.get("agent.heartbeat_seconds")).to be_nil
  end

  it "sets, changes, and clears an interval, auditing each change with the operator" do
    described_class.update_agent_intervals!(heartbeat_seconds: "120", inventory_seconds: 1800, actor: operator)
    expect(described_class.agent_intervals).to eq(heartbeat_seconds: 120, inventory_seconds: 1800)
    described_class.update_agent_intervals!(heartbeat_seconds: 60, actor: operator)
    described_class.update_agent_intervals!(heartbeat_seconds: 60, actor: operator) # unchanged: no entry
    described_class.update_agent_intervals!(heartbeat_seconds: " ", inventory_seconds: nil, actor: operator)
    expect(described_class.agent_intervals).to eq({})
    entries = AuditEntry.where(action: Audit::Actions::SETTING_CHANGED).chronological
    expect(entries.map(&:changeset)).to eq([
      { "agent.heartbeat_seconds" => [ nil, 120 ] }, { "agent.inventory_seconds" => [ nil, 1800 ] },
      { "agent.heartbeat_seconds" => [ 120, 60 ] }, { "agent.heartbeat_seconds" => [ 60, nil ] }, { "agent.inventory_seconds" => [ 1800, nil ] }
    ])
    expect(entries.map(&:actor_id).uniq).to eq([ operator.id ])
  end

  it "does nothing when clearing an interval that is not set" do
    expect { described_class.update_agent_intervals!(heartbeat_seconds: nil, actor: operator) }.not_to change(AuditEntry, :count)
  end

  it "refuses values out of range or not whole numbers, naming the field, and changes nothing" do
    [ 9, 3_601, "1.5", "abc", -1 ].each do |value|
      expect { described_class.update_agent_intervals!(inventory_seconds: 300, heartbeat_seconds: value, actor: operator) }
        .to raise_error(described_class::Invalid) { |error| expect(error.field).to eq(:heartbeat_seconds) }
    end
    expect(described_class.agent_intervals).to eq({})
  end

  it "refuses an interval it does not know" do
    expect { described_class.update_agent_intervals!(retry_seconds: 5, actor: operator) }.to raise_error(ArgumentError, /retry_seconds/)
  end

  it "shows the new settings by name in the audit log" do
    described_class.update_agent_intervals!(heartbeat_seconds: 120, actor: operator)
    expect(AuditEntriesHelper::AUDIT_FIELDS["agent.heartbeat_seconds"]).to eq([ "Seconds", true ])
  end
end
