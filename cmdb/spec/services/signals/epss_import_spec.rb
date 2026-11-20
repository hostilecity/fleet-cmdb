require "rails_helper"

# Storing FIRST's EPSS scores (VT-S03, ADR 0032): only the fleet's CVEs, the hysteresis band, older files refused, a
# truncation guard, audit, and band changes handed to the daily triage run. It never touches a finding.
RSpec.describe Signals::EpssImport do
  before do
    advisory_for("CVE-2026-90777")
    advisory_for("CVE-2026-91402", "CVE-2026-92010") # an alias counts
    Advisory.create!(advisory_id: "DSA-9999-1", source: "test", aliases: %w[CVE-2026-93330 TEMP-0001], severity: "low", modified_at: Time.current)
  end

  def band(cve_id) = EpssScore.find_by!(cve_id:).band

  it "keeps only the CVEs stored advisories name, with the model version and score date, audited" do
    import = import_epss(SignalHelpers::SIGNAL_FIXTURES.join("epss_scores-current.csv.gz"))
    expect(EpssScore.order(:cve_id).pluck(:cve_id, :band)).to eq([ %w[CVE-2026-90777 high], %w[CVE-2026-91402 high], %w[CVE-2026-92010 normal],
                                                                   %w[CVE-2026-93330 high] ])
    expect(EpssScore.find_by!(cve_id: "CVE-2026-90777")).to have_attributes(score: BigDecimal("0.94321"), percentile: BigDecimal("0.99901"),
                                                                          score_date: Date.new(2026, 11, 19))
    expect(import).to have_attributes(signal: "epss", state: "succeeded", version: "v2025.03.14", score_date: Date.new(2026, 11, 19),
                                      counts: { "rows" => 6, "valid" => 6, "malformed" => 0, "repeated" => 0, "kept" => 4, "stored" => 0, "dropped" => 0,
                                                "high" => 3, "rose" => 3, "fell" => 0 })
    expect(AuditEntry.where("action LIKE 'signal.%'").sole).to have_attributes(action: "signal.epss_imported", target_id: import.id)
    expect(pending_changes("epss")).to eq(%w[CVE-2026-90777 CVE-2026-91402 CVE-2026-93330])
  end

  it "sets the band high at 0.10, keeps it high at 0.08, and returns it to normal below 0.07 (AC)" do
    import_epss(epss_file([ %w[CVE-2026-90777 0.0999 0.5] ], date: "2026-11-15"))
    expect(band("CVE-2026-90777")).to eq("normal")
    import_epss(epss_file([ %w[CVE-2026-90777 0.10 0.5] ], date: "2026-11-16"))
    expect(band("CVE-2026-90777")).to eq("high")
    TriageSignalChange.delete_all
    import_epss(epss_file([ %w[CVE-2026-90777 0.08 0.5] ], date: "2026-11-17"))
    expect(band("CVE-2026-90777")).to eq("high")
    expect(TriageSignalChange.count).to eq(0)
    import_epss(epss_file([ %w[CVE-2026-90777 0.07 0.5] ], date: "2026-11-18"))
    expect(band("CVE-2026-90777")).to eq("high")
    import = import_epss(epss_file([ %w[CVE-2026-90777 0.0699 0.5] ], date: "2026-11-19"))
    expect(band("CVE-2026-90777")).to eq("normal")
    expect(import.counts).to include("rose" => 0, "fell" => 1, "high" => 0)
    expect(pending_changes("epss")).to eq(%w[CVE-2026-90777])
  end

  it "uses the configured thresholds" do
    saved = Signals.config.to_h.slice(:epss_enter, :epss_leave)
    Signals.config.epss_enter = 0.5
    import_epss(epss_file([ %w[CVE-2026-90777 0.4 0.5] ]))
    expect(band("CVE-2026-90777")).to eq("normal")
  ensure
    Signals.config.epss_enter = saved[:epss_enter]
  end

  it "hands a CVE that loses a high score to triage, and keeps the first row of a repeated CVE" do
    import_epss(epss_file((1..10).map { |i| [ "CVE-2026-90777", "0.#{i}", "0.5" ] }.unshift(%w[CVE-2026-91402 0.5 0.5]), date: "2026-11-18"))
    expect(EpssScore.find_by!(cve_id: "CVE-2026-90777").score).to eq(BigDecimal("0.1"))
    TriageSignalChange.delete_all
    import = import_epss(epss_file([ %w[CVE-2026-90777 0.5 0.5] ], date: "2026-11-19"), allowed_drops: 1)
    expect(import.counts).to include("dropped" => 1, "fell" => 1, "rose" => 0)
    expect(pending_changes("epss")).to eq(%w[CVE-2026-91402])
  end

  it "refuses a file older than the stored scores and stores nothing; the same date imports again" do
    import_epss(epss_file([ %w[CVE-2026-90777 0.5 0.5] ], date: "2026-11-19"))
    expect { import_epss(epss_file([ %w[CVE-2026-90777 0.01 0.5] ], date: "2026-11-18")) }
      .to raise_error(described_class::Older, "the file's scores are of 2026-11-18, older than the stored scores of 2026-11-19, so nothing was imported")
    expect(band("CVE-2026-90777")).to eq("high")
    expect(import_epss(epss_file([ %w[CVE-2026-90777 0.5 0.6] ], date: "2026-11-19")).state).to eq("succeeded")
  end

  it "holds back a file with far fewer of the fleet's CVEs, keeping the stored scores" do
    import_epss(epss_file([ %w[CVE-2026-90777 0.5 0.5], %w[CVE-2026-91402 0.5 0.5], %w[CVE-2026-92010 0.5 0.5] ], date: "2026-11-18"))
    TriageSignalChange.delete_all
    import = import_epss(epss_file([ %w[CVE-2026-90777 0.01 0.5] ], date: "2026-11-19"))
    expect(import).to have_attributes(state: "held_back", reason: "the file would drop 2 of 3 stored scores, so the previous scores are kept")
    expect(EpssScore.count).to eq(3)
    expect(band("CVE-2026-90777")).to eq("high")
    expect(TriageSignalChange.count).to eq(0)
    expect(AuditEntry.order(:id).last.action).to eq("signal.epss_import_held_back")
    expect(SignalImport.epss.succeeded.maximum(:score_date)).to eq(Date.new(2026, 11, 18))
  end

  it "rolls back a file that cannot be read part-way, keeping the stored scores" do
    import_epss(epss_file([ %w[CVE-2026-90777 0.5 0.5] ], date: "2026-11-18"))
    stub_const("Signals::EpssReader::MAX_ROWS", 2)
    stub_const("Signals::EpssImport::BATCH", 1)
    expect { import_epss(epss_file([ %w[CVE-2026-90777 0.01 0.5] ] * 3)) }.to raise_error(Advisories::Unreadable)
    expect(EpssScore.sole.score).to eq(BigDecimal("0.5"))
    expect(import_epss(epss_file([ %w[CVE-2026-90777 0.01 0.5] ])).state).to eq("succeeded")
  end
end
