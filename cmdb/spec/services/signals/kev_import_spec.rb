require "rails_helper"

# Storing CISA's KEV catalog (VT-S02, ADR 0032): replaced in one transaction, behind a truncation guard, audited, with
# what changed handed to the triage run. It never touches a finding.
RSpec.describe Signals::KevImport do
  let(:fixture) { SignalHelpers::SIGNAL_FIXTURES.join("known_exploited_vulnerabilities.json") }

  it "stores the catalog, keeps its version and counts on the import, audits it, and hands every finding to triage on the first import" do
    advisory = advisory_for("CVE-2026-90777")
    finding = open_finding_for(advisory)
    import = import_kev(fixture)
    expect(KevEntry.order(:cve_id).pluck(:cve_id, :known_ransomware)).to eq([ [ "CVE-2025-80001", false ], [ "CVE-2026-90777", true ], [ "CVE-2026-91402", false ] ])
    expect(import).to have_attributes(signal: "kev", origin: "file", source: "kev.json", state: "succeeded", version: "2026.11.19",
                                      counts: { "in_file" => 3, "stored" => 0, "added" => 3, "removed" => 0, "malformed" => 0, "repeated" => 0,
                                                "catalog_count" => 3, "added_matching" => 1 })
    expect(AuditEntry.where("action LIKE ?", "signal.%").sole).to have_attributes(action: "signal.kev_imported", actor_type: "system", target_type: "SignalImport", target_id: import.id)
    expect(pending_changes("kev")).to eq(%w[CVE-2025-80001 CVE-2026-90777 CVE-2026-91402])
    expect(pending_changes("kev_all")).to eq(%w[kev_all])
    expect(finding.reload).to have_attributes(state: "open")
    expect(advisory.reload.severity).to eq("high")
  end

  it "adds and removes entries in one transaction and hands only those CVEs to triage (AC)" do
    import_kev(kev_file(*(1..20).map { |i| format("CVE-2026-%04d", i) }))
    TriageSignalChange.delete_all
    import = import_kev(kev_file(*(2..21).map { |i| format("CVE-2026-%04d", i) }))
    expect(import.counts).to include("stored" => 20, "added" => 1, "removed" => 1)
    expect(KevEntry.pluck(:cve_id)).to include("CVE-2026-0021").and(not_include("CVE-2026-0001"))
    expect(pending_changes("kev")).to eq(%w[CVE-2026-0001 CVE-2026-0021])
    expect(pending_changes("kev_all")).to be_empty
  end

  it "rolls back the whole replacement when the import fails part-way" do
    import_kev(kev_file("CVE-2026-0001"))
    allow(SignalImport).to receive(:create!).and_raise(ActiveRecord::StatementInvalid, "boom")
    expect { import_kev(kev_file("CVE-2026-0002")) }.to raise_error(ActiveRecord::StatementInvalid)
    expect(KevEntry.pluck(:cve_id)).to eq(%w[CVE-2026-0001])
  end

  it "holds back a file missing most entries with its counts, keeping the stored catalog (AC)" do
    import_kev(kev_file(*(1..20).map { |i| format("CVE-2026-%04d", i) }))
    TriageSignalChange.delete_all
    import = import_kev(kev_file("CVE-2026-0001", "CVE-2026-0002"))
    expect(import).to have_attributes(state: "held_back", reason: "the catalog would remove 18 of 20 stored entries, so the previous catalog is kept")
    expect(import.counts).to include("stored" => 20, "removed" => 18, "added" => 0)
    expect(KevEntry.count).to eq(20)
    expect(TriageSignalChange.count).to eq(0)
    expect(AuditEntry.order(:id).last).to have_attributes(action: "signal.kev_import_held_back")
    expect(AuditEntry.order(:id).last.changeset["reason"]).to include("18 of 20")
  end

  it "allows dropping up to ALLOW_DROPS entries and no more: a ceiling, not a bypass" do
    import_kev(kev_file(*(1..20).map { |i| format("CVE-2026-%04d", i) }))
    expect(import_kev(kev_file("CVE-2026-0001"), allowed_drops: 18).state).to eq("held_back")
    expect(import_kev(kev_file("CVE-2026-0001"), allowed_drops: 19).state).to eq("succeeded")
    expect(KevEntry.count).to eq(1)
    expect(import_kev(kev_file("CVE-2026-0001", "CVE-2026-0002"), allowed_drops: 0).state).to eq("succeeded")
  end

  it "allows dropping 10% of the stored entries without a confirmation" do
    import_kev(kev_file(*(1..10).map { |i| format("CVE-2026-%04d", i) }))
    expect(import_kev(kev_file(*(2..10).map { |i| format("CVE-2026-%04d", i) })).state).to eq("succeeded")
  end
end
