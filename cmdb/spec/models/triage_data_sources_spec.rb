require "rails_helper"

# What the data sources page says about the Debian Security Tracker (P2-D08): its schedule read from
# config/recurring.yml, the releases active hosts use, and the failed refreshes since the last stored import.
RSpec.describe TriageDataSources do
  it "reads the scheduled refresh's interval, and how long after the advisory feed's it runs, from config/recurring.yml" do
    allow(Rails).to receive(:env).and_return(ActiveSupport::EnvironmentInquirer.new("production"))
    expect(described_class.schedule).to eq([ 6.hours.to_i, 15.minutes.to_i ])
    expect(ApplicationController.helpers.triage_schedule_text(described_class.schedule))
      .to eq("Every 6 hours, 15 minutes after the advisory feed's refresh; up to 5 attempts with backoff")
    expect(ApplicationController.helpers.triage_schedule_text([ 6.hours.to_i, nil ])).to eq("Every 6 hours; up to 5 attempts with backoff")
  end

  it "has no schedule in an environment that does not schedule the refresh" do
    expect(described_class.schedule).to be_nil
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
