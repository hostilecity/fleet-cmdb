require "rails_helper"

# The advisory data freshness indicator on the fleet page (P2-S13): stale data must not pass for no findings.
RSpec.describe "Advisory data freshness", :signed_in, type: :request do
  def indicator = page.at_css("#advisory_freshness")

  def refreshed(at:, full: true, state: "succeeded", ecosystems: [ "Debian:13" ])
    AdvisoryImport.create!(origin: "feed", source: "storage.example.org/osv/Debian/all.zip", full:, state:, ecosystems:, started_at: at, finished_at: at)
  end

  it "warns when no full refresh has ever succeeded, whatever partial imports and failures there were" do
    refreshed(at: 1.hour.ago, full: false)
    refreshed(at: 1.hour.ago, state: "failed", ecosystems: [])
    get "/"
    expect(indicator["class"]).to eq("notice")
    expect(indicator.text.squish).to include("Vulnerability data has never been refreshed.", "Debian:13 advisory data has never been updated from the feed or a full import")
    expect(indicator.at_css("a")["href"]).to eq("/jobs/failed")
  end

  it "warns when the data is older than the threshold, with when it was last updated" do
    at = Time.current - Advisories.config.max_age - 1.hour
    refreshed(at:)
    get "/"
    expect(indicator.text.squish).to include("Vulnerability data is out of date.", "Debian:13 advisory data was last updated 2 days ago (#{at.utc.strftime('%Y-%m-%d %H:%M UTC')})")
  end

  it "says when the data was last updated, without a warning, while it is fresh" do
    refreshed(at: 3.hours.ago)
    get "/"
    expect(indicator["class"]).to eq("muted")
    expect(indicator.text.squish).to eq("Advisory data last updated: Debian:13 about 3 hours ago.")
  end

  it "uses the configured threshold" do
    refreshed(at: 3.hours.ago)
    expect(Advisories::Freshness.statuses(max_age: 2.hours).sole.stale).to be(true)
    expect(Advisories::Freshness.stale?(max_age: 4.hours)).to be(false)
  end
end
