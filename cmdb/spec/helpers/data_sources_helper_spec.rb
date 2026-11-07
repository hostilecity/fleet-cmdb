require "rails_helper"

# The scheduled feed in words on the Advisory data sources page (P2-D06, data-sources.html).
RSpec.describe DataSourcesHelper, type: :helper do
  let(:feed) { AdvisoryDataSources::FeedInfo.new(source: "feeds.example.lan/osv/Debian/all.zip", schedule: 6.hours.to_i, attempts: 5, max_age: 48.hours, token: false) }

  it "says how often the feed is refreshed and how many attempts each refresh gets" do
    expect(helper.feed_schedule_text(feed)).to eq("Every 6 hours, up to 5 attempts with backoff")
  end

  it "says when this environment does not schedule the refresh" do
    expect(helper.feed_schedule_text(feed.with(schedule: nil))).to eq("Not scheduled in this environment; run bin/rails advisories:refresh")
  end
end
