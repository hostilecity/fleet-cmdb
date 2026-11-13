require "rails_helper"

# What the data sources page says about the Debian Security Tracker (P2-D08): its schedule read from
# config/recurring.yml, the releases active hosts use, and the failed refreshes since the last stored import.
RSpec.describe TriageDataSources do
  it "reads the scheduled refresh's interval, and how long after the advisory feed's it runs, from config/recurring.yml" do
    allow(Rails).to receive(:env).and_return(ActiveSupport::EnvironmentInquirer.new("production"))
    expect(described_class.schedule).to eq([ 6.hours.to_i, 15.minutes.to_i ])
  end

  it "says when the scheduled refresh runs next, in one line (#148)" do
    allow(Rails).to receive(:env).and_return(ActiveSupport::EnvironmentInquirer.new("production"))
    now = Time.utc(2026, 11, 7, 2, 0)
    # "56 */6 * * *", in the server's time zone as Solid Queue runs it.
    next_at = described_class.next_refresh(now)
    expect([ next_at.min, next_at.hour % 6, (next_at - now).between?(0, 6.hours) ]).to eq([ 56, 0, true ])
    helpers = ApplicationController.helpers
    expect(helpers.triage_refresh_text(described_class.schedule, now + 4.hours, now)).to eq("Next refresh in about 4 hours (every 6 hours, after the advisory feed)")
    expect(helpers.triage_refresh_text([ 6.hours.to_i, nil ], now + 3.minutes, now)).to eq("Next refresh in 3 minutes (every 6 hours)")
  end

  it "has no schedule in an environment that does not schedule the refresh" do
    expect(described_class.schedule).to be_nil
    expect(described_class.next_refresh).to be_nil
    expect(ApplicationController.helpers.triage_refresh_text(nil, nil)).to eq("Not scheduled in this environment")
  end

  it "lists only the releases active hosts use, with entries counted by no-DSA reason" do
    debian_host(packages: nil)
    debian_host(name: "Old", hostname: "vm-02.example.lan", packages: nil, os: { "id" => "debian", "version_id" => "12", "pretty_name" => "Debian 12" })
    debian_host(name: "Other", hostname: "vm-03.example.lan", packages: nil, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu" })
    import_triage(tracker_document("glibc" => {
      "CVE-2026-0001" => { "trixie" => tracker_release(nodsa: "Minor issue"), "bookworm" => tracker_release(nodsa: "Minor issue", nodsa_reason: "postponed") },
      "CVE-2026-0002" => { "trixie" => tracker_release(nodsa: "Not worth it", nodsa_reason: "ignored"), "bookworm" => tracker_release(status: "resolved", fixed_version: "1") }
    }))
    rows = described_class.new.releases
    expect(rows.map { |row| [ row.release, row.name, row.ecosystem, row.hosts, row.entries, row.open, row.no_dsa, row.postponed, row.ignored, row.held ] })
      .to eq([ [ "bookworm", "Debian 12", nil, 1, 2, 1, 0, 1, 0, false ], [ "trixie", "Debian 13", "Debian:13", 1, 2, 2, 1, 0, 1, false ] ])
  end

  it "counts the scheduled refreshes that failed since the last import that stored data" do
    at = ->(time, state) { TriageImport.create!(tracker: "debian", origin: "feed", source: "x/json", state:, releases: (state == "failed" ? [] : [ "trixie" ]), started_at: time, finished_at: time) }
    at.(5.days.ago, "failed")
    expect(described_class.new.failed_refreshes).to eq(1)
    at.(4.days.ago, "succeeded")
    at.(3.days.ago, "failed")
    at.(2.days.ago, "failed")
    TriageImport.create!(tracker: "debian", origin: "file", source: "json", state: "failed", started_at: 1.day.ago, finished_at: 1.day.ago)
    expect(described_class.new.failed_refreshes).to eq(2)
  end
end
