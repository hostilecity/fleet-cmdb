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
    # states-empty.html#freshness: the warning links to the fix, the data sources page (P2-D06).
    expect(indicator.at_css("a").text).to eq("Refresh it or upload a file")
    expect(indicator.at_css("a")["href"]).to eq("/data-sources")
  end

  it "warns when the data is older than the threshold, with when it was last updated" do
    at = Time.current - Advisories.config.max_age - 1.hour
    refreshed(at:)
    get "/"
    expect(indicator.text.squish).to include("Vulnerability data is out of date.", "Debian:13 advisory data was last updated 2 days ago (#{at.utc.strftime('%Y-%m-%d %H:%M UTC')})")
    expect(indicator.at_css("a").text).to eq("See the data sources")
  end

  it "says automatic refresh is off, rather than warning, when no feed is configured (states-empty.html#freshness)" do
    saved = Advisories.config.feed_url
    Advisories.config.feed_url = nil
    refreshed(at: 5.days.ago)
    get "/"
    expect(indicator["class"]).to eq("notice info")
    expect(indicator.text.squish).to eq("Automatic advisory refresh is off. No feed is configured on the server, so advisory data changes only when you upload a file. " \
                                        "Debian:13 was last updated 5 days ago, which is older than 48 hours. Upload a file.")
    expect(indicator.at_css("a")["href"]).to eq("/data-sources#up")
  ensure
    Advisories.config.feed_url = saved
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
