require "rails_helper"

# How old each signal's data is (VT-S02, VT-S03): read-time only, and never a reason to rewrite anything (B1).
RSpec.describe Signals::Freshness do
  def stored(signal, at:, state: "succeeded", **attributes)
    SignalImport.create!(signal:, origin: "feed", source: "example.org/x", state:, started_at: at, finished_at: at, **attributes)
  end

  it "is never imported until an import succeeds, fresh after one, and stale past FLEET_SIGNAL_MAX_AGE_HOURS" do
    expect(described_class.status("kev")).to have_attributes(never?: true, stale: true, configured: true)
    stored("kev", at: 3.hours.ago, version: "2026.11.19")
    expect(described_class.status("kev")).to have_attributes(never?: false, stale: false, version: "2026.11.19")
    travel 8.days do
      expect(described_class.status("kev")).to have_attributes(stale: true, updated_at: be_present)
    end
  end

  it "is not refreshed by a held-back or failed import, and counts the failed refreshes since the last success" do
    stored("kev", at: 9.days.ago)
    stored("kev", at: 2.days.ago, state: "held_back")
    stored("kev", at: 1.day.ago, state: "failed")
    stored("kev", at: 1.hour.ago, state: "failed")
    expect(described_class.status("kev").stale).to be(true)
    expect(described_class.failed_refreshes("kev")).to eq(2)
    expect(described_class.held_import("kev").finished_at).to be_within(1.minute).of(2.days.ago)
    stored("kev", at: 1.minute.ago)
    expect(described_class.held_import("kev")).to be_nil
    expect(described_class.failed_refreshes("kev")).to eq(0)
    expect(described_class.failed_refreshes("epss")).to eq(0)
  end

  it "is stale for EPSS when the stored score date is past the limit, even after a recent not-modified answer" do
    stored("epss", at: 1.hour.ago, score_date: 10.days.ago.to_date, counts: { "not_modified" => true })
    expect(described_class.status("epss")).to have_attributes(stale: true, score_date: 10.days.ago.to_date)
    stored("epss", at: 1.minute.ago, score_date: Date.current)
    expect(described_class.status("epss").stale).to be(false)
  end

  it "says when a source is turned off, keeping its last data's date" do
    stored("epss", at: 1.hour.ago, score_date: Date.current)
    saved = Signals.config.epss_url
    Signals.config.epss_url = nil
    expect(described_class.statuses.last).to have_attributes(signal: "epss", off?: true, never?: false)
  ensure
    Signals.config.epss_url = saved
  end
end
