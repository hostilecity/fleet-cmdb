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

  it "refuses to release inside an open transaction, where the delete would go with the run's transaction" do
    described_class.record!(:kev, cve_ids: %w[CVE-2026-0001]) # this example runs inside the test's transaction
    expect { described_class.release!(described_class.pluck(:id)) }.to raise_error(ArgumentError, /must run outside a transaction/)
    expect(described_class.count).to eq(1)
  end
end
