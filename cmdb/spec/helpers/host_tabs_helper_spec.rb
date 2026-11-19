require "rails_helper"

# The reports tile on every host tab (P2-D02, owner decision Q1): each report type with its own age, headed by the
# oldest, because the types arrive on different intervals.
RSpec.describe HostTabsHelper, type: :helper do
  let(:now) { Time.utc(2026, 11, 6, 12, 0, 0) }
  let(:summary) { instance_double(HostSummary) }

  before do
    helper.extend(ReportRequestsHelper)
    travel_to(now)
  end

  def received(times)
    received = HostSummary::REPORT_TYPES.index_with { |type| times[type] }
    allow(summary).to receive_messages(received:, oldest_received_at: received.values.compact.min, received_count: received.values.compact.size)
  end

  it "gives each type its own age in a fixed order, and heads them with the oldest" do
    received("inventory" => now - 45.seconds, "packages" => now - 5.hours, "config" => now - 3.hours)
    expect(helper.report_ages(summary)).to eq("Config about 3 hours ago · packages about 5 hours ago · inventory less than a minute ago")
    expect(helper.oldest_report_age(summary)).to eq("<small>oldest</small> about 5 hours ago")
  end

  it "says no report yet for a type never received, and leaves it out of the oldest" do
    received("inventory" => now - 1.minute, "config" => now - 2.hours)
    expect(helper.report_ages(summary)).to eq("Config about 2 hours ago · no package report yet · inventory 1 minute ago")
    expect(helper.oldest_report_age(summary)).to eq("<small>oldest</small> about 2 hours ago")
  end

  it "does not call a single report the oldest" do
    received("inventory" => now - 1.minute)
    expect(helper.report_ages(summary)).to eq("No config report yet · no package report yet · inventory 1 minute ago")
    expect(helper.oldest_report_age(summary)).to eq("1 minute ago")
  end
end
