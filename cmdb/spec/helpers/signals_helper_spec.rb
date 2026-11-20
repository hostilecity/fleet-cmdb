require "rails_helper"

# The exploitation signals in words (VT-D03, VT-S04; review of #269).
RSpec.describe SignalsHelper, type: :helper do
  def status(**attributes)
    Signals::Freshness::Status.new(**{ signal: "kev", updated_at: 30.days.ago, stale: true, version: nil, score_date: nil, configured: false }.merge(attributes))
  end

  it "says a turned-off source past the age limit is out of date, and marks it stale" do
    expect(helper.signal_freshness_text(status)).to eq("Known exploited (CISA KEV): turned off on this server; the last data, about 1 month ago, is out of date and still used.")
    expect(helper.signal_freshness_line([ status ])).to include('class="stale-word"')
    expect(helper.signal_freshness_text(status(stale: false))).to end_with("is kept and still used.")
  end

  it "gives the age limit in days when it is whole days, otherwise in hours" do
    expect(helper.signal_hours).to eq("7 days")
    saved = Signals.config.max_age
    Signals.config.max_age = 30.hours
    expect(helper.signal_hours).to eq("30 hours")
  ensure
    Signals.config.max_age = saved
  end

  it "puts a CVSS vector's parts in words, and nothing without one (VT-S04)" do
    expect(helper.signal_vector_words(Advisory.new(cvss_av: "N", cvss_pr: "N", cvss_ui: "N"))).to eq("network, no login, no user action")
    expect(helper.signal_vector_words(Advisory.new(cvss_av: "L", cvss_pr: "H", cvss_ui: "R"))).to eq("local, an administrator login, a user's action")
    expect(helper.signal_vector_words(Advisory.new)).to be_nil
  end

  it "says what happened to the matching count: counted, being counted, too large to count, or failed, with its time" do
    at = Time.utc(2026, 11, 20, 6, 0)
    panel = ->(counts, entries: 3) do
      SignalDataSources::Panel.new(signal: "kev", status: status, source: nil, entries:, high: nil, latest: SignalImport.new(counts:), held: nil, failed: 0,
                                   imports: [], next_refresh: nil)
    end
    travel_to(at + 2.hours) do
      expect(helper.signal_matching_text(panel.({ "matching_state" => "counted", "matching" => 2, "matching_at" => at.iso8601 })))
        .to eq("of which 2 match open findings in this fleet (counted about 2 hours ago, after the last import)")
      expect(helper.signal_matching_text(panel.({}))).to eq("how many match open findings is being counted")
      expect(helper.signal_matching_text(panel.({ "matching_state" => "timed_out", "matching_at" => at.iso8601 })))
        .to eq("too large to count how many match open findings (stopped after 5 minutes, about 2 hours ago, 2026-11-20 06:00 UTC); bin/rails signals:recount tries again")
      expect(helper.signal_matching_text(panel.({ "matching_state" => "failed", "matching_at" => at.iso8601 })))
        .to eq("count of those matching open findings failed (about 2 hours ago, 2026-11-20 06:00 UTC); bin/rails signals:recount tries again")
      expect(helper.signal_matching_text(panel.({}, entries: 0))).to eq("none matching open findings")
    end
  end

  # Re-review of #269: an EPSS reset's row named KEV's task and rules.
  it "describes an EPSS reset as an EPSS reset, and a KEV clear as a KEV clear" do
    epss = Signals.clear!("epss")
    expect(helper.signal_import_how(epss)).to eq("bin/rails signals:epss_reset")
    expect(helper.signal_import_summary(epss)).to eq("0 deleted. #{Signals::CLEARED['epss']}")
    expect(helper.signal_import_summary(epss)).to include("rule N2").and(not_include("KEV"))
    kev = Signals.clear!("kev")
    expect(helper.signal_import_how(kev)).to eq("bin/rails signals:kev_clear")
    expect(helper.signal_import_summary(kev)).to include("rule N1", "rule I5")
  end
end
