require "rails_helper"

# When the host reports tile calls a report type on schedule, overdue, missing, or awaited (owner decision on #255).
RSpec.describe ReportSchedule do
  let(:now) { Time.utc(2026, 11, 6, 12, 0, 0) }

  def state(received_at, first_seen_at: now - 1.day, interval: 21_600)
    described_class.state(received_at:, interval:, first_seen_at:, now:)
  end

  it "calls a report overdue once it is older than twice its interval" do
    expect(state(now - 12.hours)).to eq(:on_schedule)
    expect(state(now - 12.hours - 1.second)).to eq(:overdue)
  end

  it "awaits a type never received for one interval after the host was first seen, then calls it missing" do
    expect(state(nil, first_seen_at: now - 6.hours)).to eq(:awaited)
    expect(state(nil, first_seen_at: now - 6.hours - 1.second)).to eq(:missing)
    expect(state(nil, first_seen_at: nil)).to eq(:awaited)
  end

  it "uses the agent's defaults, with the operator's inventory interval when one is set" do
    expect(described_class.intervals).to eq("config" => 21_600, "packages" => 21_600, "inventory" => 900)
    Setting.update_agent_intervals!(actor: Audit::SYSTEM, inventory_seconds: 3600)
    expect(described_class.intervals).to eq("config" => 21_600, "packages" => 21_600, "inventory" => 3600)
  end
end
