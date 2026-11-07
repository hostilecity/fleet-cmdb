require "rails_helper"

# What the Advisory data sources page says about the scheduled feed (P2-D06): its interval is read from
# config/recurring.yml for the environment, so the page cannot drift from the schedule that actually runs.
RSpec.describe AdvisoryDataSources do
  it "reads the scheduled refresh's interval from config/recurring.yml" do
    allow(Rails).to receive(:env).and_return(ActiveSupport::EnvironmentInquirer.new("production"))
    expect(described_class.schedule_interval).to eq(6.hours.to_i)
    expect(described_class.new.feed).to have_attributes(schedule: 6.hours.to_i, attempts: ApplicationJob::ATTEMPTS)
  end

  it "has no interval in an environment that does not schedule the refresh" do
    expect(described_class.schedule_interval).to be_nil
  end

  it "counts the feed refreshes that failed since the last one that succeeded" do
    at = ->(time, state) { AdvisoryImport.create!(origin: "feed", source: "feeds.example.lan/all.zip", full: true, state:, started_at: time, finished_at: time) }
    at.(5.days.ago, "failed")
    at.(4.days.ago, "succeeded")
    at.(3.days.ago, "failed")
    at.(2.days.ago, "failed")
    AdvisoryImport.create!(origin: "file", source: "x.zip", state: "failed", started_at: 1.day.ago, finished_at: 1.day.ago)
    expect(described_class.new.failed_refreshes).to eq(2)
  end
end
