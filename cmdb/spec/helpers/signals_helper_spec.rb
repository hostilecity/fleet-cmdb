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

  it "says when matching open findings has not been counted" do
    import = SignalImport.new(counts: { "matching_timed_out" => true })
    panel = SignalDataSources::Panel.new(signal: "kev", status: status, source: nil, entries: 3, high: nil, latest: import, held: nil, failed: 0, imports: [], next_refresh: nil)
    expect(helper.signal_matching_text(panel)).to eq("how many match open findings is not counted yet")
    expect(helper.signal_matching_text(panel.with(entries: 0))).to eq("none matching open findings")
    expect(helper.signal_matching_text(panel.with(latest: SignalImport.new(counts: { "matching" => 2 })))).to eq("of which 2 match open findings in this fleet")
  end
end
