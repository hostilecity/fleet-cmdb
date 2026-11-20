require "rails_helper"

# The hand-off to the triage run (VT-S05): one pending row per kind and CVE or advisory, so changes coalesce.
RSpec.describe TriageSignalChange do
  it "records each change once, whatever how often it is recorded" do
    described_class.record!(:kev, cve_ids: %w[CVE-2026-0001 CVE-2026-0001 CVE-2026-0002])
    described_class.record!(:kev, cve_ids: %w[CVE-2026-0002])
    described_class.record!(:epss, cve_ids: %w[CVE-2026-0002])
    described_class.record!(:advisory, advisory_ids: [ 7, "7", 8 ])
    described_class.record!(:kev_all)
    described_class.record!(:kev_all)
    described_class.record!(:epss, cve_ids: [])
    expect(pending_changes("kev")).to eq(%w[CVE-2026-0001 CVE-2026-0002])
    expect(pending_changes("epss")).to eq(%w[CVE-2026-0002])
    expect(pending_changes("advisory")).to eq(%w[7 8])
    expect(pending_changes("kev_all")).to eq(%w[kev_all])
  end

  it "refuses an unknown kind, and the database refuses a row without its target" do
    expect { described_class.record!(:other) }.to raise_error(ArgumentError, "unknown kind other")
    expect { described_class.create!(kind: "kev", created_at: Time.current) }.to raise_error(ActiveRecord::StatementInvalid, /triage_signal_changes_target_valid/)
    expect(described_class.new(kind: "x")).not_to be_valid
  end

  # Review of #269: with the first id kept, a consumer that read, worked, then deleted by id lost a change recorded in
  # between. Every record gives the row a new id, and release! deletes only the ids claimed.
  it "never loses a change recorded between a claim and its release" do
    described_class.record!(:kev, cve_ids: %w[CVE-2026-0001 CVE-2026-0002])
    described_class.record!(:advisory, advisory_ids: [ 7 ])
    described_class.record!(:kev_all)
    claimed = described_class.claim(kinds: %w[kev kev_all], limit: 10)
    expect(claimed.map { |c| c.cve_id || c.kind }).to eq(%w[CVE-2026-0001 CVE-2026-0002 kev_all])
    described_class.record!(:kev, cve_ids: %w[CVE-2026-0001]) # recorded again while the run works
    described_class.record!(:kev_all)
    expect(described_class.release!(claimed.map(&:id))).to eq(1)
    expect(pending_changes("kev")).to eq(%w[CVE-2026-0001])
    expect(pending_changes("kev_all")).to eq(%w[kev_all])
    expect(pending_changes("advisory")).to eq(%w[7])
    expect(described_class.claim(limit: 1).map(&:kind)).to eq(%w[advisory]) # oldest first
  end
end
