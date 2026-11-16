require "rails_helper"

# The heartbeat's directives in one statement (#189).
RSpec.describe HeartbeatDirectives do
  it "reads the rollout offer with the columns Rollouts builds its directive from, in the same order" do
    expect(described_class::OFFER_JSON).to eq("json_build_array(#{Rollouts::OFFER_COLUMNS.join(', ')})")
  end
end

RSpec.describe HeartbeatDirectives, "statement" do
  # The same text for every host and every heartbeat, with the values as bind parameters, so PostgreSQL prepares it
  # once per connection and does not plan it on every heartbeat (review of #209).
  it "is one prepared statement whose text does not change with the host or the time" do
    calls = []
    callback = ->(*, payload) { calls << payload if payload[:name] == "HeartbeatDirectives" }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") do
      ApplicationRecord.transaction do
        described_class.lookup(host_id: 11, agent_version: "0.1.0", agent_time: Time.current, now: Time.current)
        described_class.lookup(host_id: 12, agent_version: "0.1.0", agent_time: Time.current, now: 1.minute.from_now)
      end
    end
    expect(calls.size).to eq(2)
    expect(calls.map { |c| c[:sql] }.uniq.size).to eq(1)
    expect(calls.first[:sql]).to include("$1").and(include("rollout_hosts")).and(include("EXISTS"))
    expect(calls.first[:sql]).not_to match(/FOR (SHARE|UPDATE)/) # no rollout row lock per heartbeat (#199)
    expect(calls.first[:sql]).not_to match(/'\d{4}-\d\d-\d\d|= 11\b/) # no inlined time or host id
    expect(calls.map { |c| c[:binds].map(&:value) }).to all(include(11).or(include(12)))
    prepared = ApplicationRecord.connection.select_values("SELECT statement FROM pg_prepared_statements")
    expect(prepared).to include(calls.first[:sql])
  end
end
