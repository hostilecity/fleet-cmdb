require "rails_helper"

# How old each release's Debian triage is (P2-S16): its own last success, apart from OSV's.
RSpec.describe DebianTriage::Freshness do
  def curl(n, releases: %w[trixie bookworm])
    tracker_document("curl" => (1..n).to_h { |i| [ "CVE-2026-#{10_000 + i}", releases.index_with { tracker_release } ] })
  end

  it "is never refreshed, then fresh per release stored, then stale past FLEET_ADVISORY_MAX_AGE_HOURS" do
    expect(described_class.statuses.map { |s| [ s.release, s.never?, s.stale ] }).to eq(%w[bookworm forky sid trixie].map { |r| [ r, true, true ] })
    import_triage(curl(10))
    expect(described_class.statuses.map(&:stale)).to all(be(false))
    expect(Advisories::Freshness.statuses.sole).to be_never # OSV's freshness is its own
    travel 49.hours do
      expect(described_class.statuses.map(&:stale)).to all(be(true))
    end
  end

  it "does not refresh a release a held-back import kept back, and names that import until one succeeds" do
    import_triage(curl(10))
    travel 1.hour do
      held = import_triage(curl(10, releases: %w[bookworm]))
      expect(held.state).to eq("held_back")
      statuses = described_class.statuses.index_by(&:release)
      expect(statuses["bookworm"].updated_at).to be > statuses["trixie"].updated_at
      expect(described_class.held_import).to eq(held)
    end
    travel 2.hours do
      import_triage(curl(10))
      expect(described_class.held_import).to be_nil
    end
  end

  it "names a held-back import when none has succeeded" do
    TriageImport.create!(tracker: "debian", origin: "feed", source: "x/json", state: "held_back", started_at: Time.current, finished_at: Time.current)
    expect(described_class.held_import).to be_present
  end
end
