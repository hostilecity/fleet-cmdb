require "rails_helper"

# The exploitation signals' shared parts (VT-SIGNALS, ADR 0032): clearing KEV data, counting CVEs that match open
# findings, recording failures, and the truncation guard's rule.
RSpec.describe Signals do
  describe ".clear_kev!" do
    it "deletes the stored entries, hands every finding to triage, audits what it means, and reads as never imported" do
      import_kev(kev_file("CVE-2026-0001", "CVE-2026-0002"))
      TriageSignalChange.delete_all
      operator = create(:operator)
      import = described_class.clear_kev!(operator:)
      expect(KevEntry.count).to eq(0)
      expect(import).to have_attributes(signal: "kev", origin: "task", state: "cleared", counts: { "deleted" => 2 }, operator:)
      expect(pending_changes("kev_all")).to eq(%w[kev_all])
      entry = AuditEntry.where(action: "signal.kev_cleared").sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id)
      expect(entry.changeset["reason"]).to include("rule N1", "rule I5", "stop applying")
      expect(Signals::Freshness.status("kev")).to be_never
      expect(Signals::Freshness).not_to be_kev_imported
    end
  end

  describe ".matching_open_findings" do
    it "counts the CVEs an advisory with an open or reopened finding names, by its id or an alias, each once" do
      open_finding_for(advisory_for("CVE-2026-0001", "CVE-2026-0002"))
      open_finding_for(Advisory.create!(advisory_id: "DSA-1-1", source: "t", aliases: %w[CVE-2026-0003 CVE-2026-0001], severity: "low", modified_at: Time.current),
                       state: "reopened")
      open_finding_for(advisory_for("CVE-2026-0004"), state: "resolved")
      advisory_for("CVE-2026-0005")
      expect(described_class.matching_open_findings(%w[CVE-2026-0001 CVE-2026-0002 CVE-2026-0003 CVE-2026-0004 CVE-2026-0005 CVE-2026-0006])).to eq(3)
      expect(described_class.matching_open_findings([])).to eq(0)
      import_kev(kev_file("CVE-2026-0003", "CVE-2026-0004"))
      expect(described_class.matching_open_findings("SELECT cve_id FROM kev_entries")).to eq(1)
    end
  end

  describe ".too_many_dropped?" do
    it "holds back past FLEET_ADVISORY_WITHDRAW_SHARE of the stored entries, or past an operator's ceiling once one is given" do
      expect(described_class.too_many_dropped?(dropped: 10, stored: 100, allowed: nil)).to be(false)
      expect(described_class.too_many_dropped?(dropped: 11, stored: 100, allowed: nil)).to be(true)
      expect(described_class.too_many_dropped?(dropped: 50, stored: 100, allowed: 50)).to be(false)
      expect(described_class.too_many_dropped?(dropped: 5, stored: 100, allowed: 4)).to be(true)
      expect(described_class.too_many_dropped?(dropped: 0, stored: 0, allowed: nil)).to be(false)
    end
  end

  it "records a failure with a cleaned source, audited, for either signal" do
    import = described_class.record_failure("epss", reason: "x" * 600, origin: "file", source: "bad\u0000name.csv")
    expect(import).to have_attributes(state: "failed", source: "bad name.csv", reason: have_attributes(length: 512))
    expect(AuditEntry.sole.action).to eq("signal.epss_import_failed")
    expect(described_class.record_failure("kev", reason: "r", origin: "feed", source: nil).source).to eq("unknown")
  end
end
