require "rails_helper"

# The exploitation signal panels on the Data sources page and the freshness line (VT-D03, #257; approved mockup
# docs/mockups/vuln-triage/data-sources.html): up to date, stale, turned off, never imported, and held back, with every
# feed value escaped and only each source's host and path shown.
RSpec.describe "Data sources: exploitation signals", :signed_in, type: :request do
  around do |example|
    saved = Signals.config.to_h.slice(:kev_url, :epss_url)
    advisories = Advisories.config.feed_url
    Advisories.config.feed_url = "https://feeds.example.lan/osv/Debian/all.zip"
    Signals.config.kev_url = "https://user:pass-secret@kev.example.lan/cisagov/kev.json?token=query-secret"
    Signals.config.epss_url = "https://epss.example.lan/epss_scores-current.csv.gz"
    example.run
  ensure
    Signals.config.kev_url, Signals.config.epss_url = saved.values_at(:kev_url, :epss_url)
    Advisories.config.feed_url = advisories
  end

  def facts(scope) = scope.css("dt").map { |dt| dt.text.squish }.zip(scope.css("dd").map { |dd| dd.text.squish }).to_h

  def panel(id) = page.at_css("##{id}_panel")

  it "shows both panels up to date, with entries, matches, crossings, the source's host and path only, the attribution, and latest imports" do
    advisory = advisory_for("CVE-2026-90777")
    open_finding_for(advisory)
    advisory_for("CVE-2026-93330")
    import_kev(SignalHelpers::SIGNAL_FIXTURES.join("known_exploited_vulnerabilities.json"), origin: "feed", source: "kev.example.lan/cisagov/kev.json")
    import_epss(SignalHelpers::SIGNAL_FIXTURES.join("epss_scores-current.csv.gz"), origin: "feed", source: "epss.example.lan/epss_scores-current.csv.gz")
    travel_to Time.utc(2026, 11, 19, 18, 0) do
      get "/data-sources"
    end
    expect(response).to have_http_status(:ok)
    expect(page.at_css("h1").text).to eq("Data sources")
    kev = facts(panel("kev").at_css("dl"))
    expect(kev["Freshness"]).to start_with("Up to date · last success").and(end_with("catalog version 2026.11.19"))
    expect(kev["Entries"]).to eq("3 CVEs, of which 1 matches open findings in this fleet")
    expect(kev["Source"]).to start_with("kev.example.lan/cisagov/kev.json · every 6 hours with the advisory refresh, conditional request")
    expect(panel("kev").to_html).not_to include("pass-secret", "query-secret", "user:")
    epss = facts(panel("epss").at_css("dl"))
    expect(epss["Freshness"]).to include("Up to date", "scores of 2026-11-19", "model v2025.03.14")
    expect(epss["Entries"]).to eq("Only CVEs named by advisories in the database are kept: 2 of 6 in the last file. 2 at or above the threshold, of which 1 matches open findings")
    expect(epss["Crossed the threshold"]).to eq("2 rose to 10% or more; 0 fell below 7% (scores of 2026-11-19)")
    expect(epss["Source"]).to start_with("epss.example.lan/epss_scores-current.csv.gz · daily at 14:30 UTC · redirects followed only")
    expect(page.at_css("#epss_attribution").text).to eq("See EPSS at https://www.first.org/epss")
    expect(panel("kev").css("#kev_import_list tbody tr td").map(&:text).map(&:squish))
      .to include("Scheduled refresh", "Imported", "3 added (1 matches open findings: handed to triage); 0 removed; 3 in the catalog", "System")
    expect(panel("epss").at_css("#epss_import_list tbody tr td:nth-child(4)").text.squish).to eq("2 kept of 6 rows; 2 rose to 10% or more; 0 fell below 7%")
    expect(panel("kev").at_css(".state-note").text.squish).to include("Refresh now above refreshes it too", "bin/rails signals:kev_import FILE=...")
    expect(page.css("#kev_stale, #kev_off, #kev_held, #epss_stale")).to be_empty
    expect(page.at_css("#signal_freshness").text.squish).to match(/Known exploited \(CISA KEV\): .+ ago\. Exploit prediction \(FIRST EPSS\): scores of 2026-11-19\./)
  end

  it "says when a source was never imported, and that nothing is checked against it yet" do
    get "/data-sources"
    expect(panel("kev").at_css("#kev_stale").text.squish).to start_with("Never imported on this server. No finding is checked against it yet, and findings Debian rates unimportant")
    expect(panel("epss").at_css("#epss_stale").text.squish).to start_with("Never imported on this server.")
    expect(facts(panel("kev").at_css("dl"))["Freshness"]).to eq("Never imported")
    expect(panel("kev").at_css("#kev_no_imports").text).to eq("Nothing imported yet.")
    expect(page.at_css("#signal_freshness").text.squish).to eq("Known exploited (CISA KEV): not imported yet. Exploit prediction (FIRST EPSS): not imported yet.")
  end

  it "shows stale data as out of date and still used, with the failed refreshes, without moving anything" do
    failure = -> { Signals.record_failure("kev", reason: "the CISA KEV catalog at kev.example.lan answered HTTP 503", origin: "feed", source: "kev.example.lan/cisagov/kev.json") }
    travel_to(9.days.ago) do
      import_kev(kev_file("CVE-2026-0001"), origin: "feed", source: "kev.example.lan/cisagov/kev.json")
    end
    travel_to(8.days.ago) { failure.call }
    failure.call
    begin
      expect { get "/data-sources" }.not_to(change { [ KevEntry.count, TriageSignalChange.count ] })
      notice = panel("kev").at_css("#kev_stale").text.squish
      expect(notice).to start_with("Out of date, still used. Last refreshed 9 days ago")
      expect(notice).to include("Triage keeps using this data; no finding moves because the source is late.", "The last 2 refreshes failed")
      expect(facts(panel("kev").at_css("dl"))["Freshness"]).to start_with("Out of date: older than 168 hours · last success 9 days ago")
      expect(panel("kev").at_css("#kev_import_list tbody tr td:nth-child(4)").text).to eq("Nothing imported: the CISA KEV catalog at kev.example.lan answered HTTP 503")
      expect(page.at_css("#signal_freshness").text.squish).to start_with("Known exploited (CISA KEV): out of date (9 days ago); still used until refreshed.")
      expect(page.at_css("#signal_freshness .stale-word")).to be_present
    end
  end

  it "says a turned-off source keeps its last data, which is still used, and offers no schedule or source" do
    advisory_for("CVE-2026-0001")
    import_epss(epss_file([ %w[CVE-2026-0001 0.2 0.5] ]))
    Signals.config.epss_url = nil
    Signals.config.kev_url = nil
    get "/data-sources"
    expect(panel("epss").at_css("#epss_off").text.squish).to eq("Turned off on this server. The last data, scores of 2026-11-19, is kept and still used; it shows as out of date. " \
                                                                "Its data changes only when a file is imported on the server.")
    expect(panel("kev").at_css("#kev_off").text.squish).to start_with("Turned off on this server. Nothing has been imported")
    expect(facts(panel("epss").at_css("dl"))).not_to have_key("Source")
    expect(panel("epss").at_css(".state-note").text).not_to include("Refresh now")
    expect(page.at_css("#signal_freshness").text.squish)
      .to eq("Known exploited (CISA KEV): turned off on this server, never imported. " \
             "Exploit prediction (FIRST EPSS): turned off on this server; the last data, scores of 2026-11-19, is kept and still used.")
  end

  it "shows a held-back refresh with its counts and the exact allowance, keeping the previous data" do
    import_kev(kev_file(*(1..20).map { |i| format("CVE-2026-%04d", i) }), origin: "feed", source: "kev.example.lan/cisagov/kev.json")
    import_kev(kev_file("CVE-2026-0001"), origin: "feed", source: "kev.example.lan/cisagov/kev.json")
    get "/data-sources"
    held = panel("kev").at_css("#kev_held").text.squish
    expect(held).to eq("The last refresh was held back. Held back: it would remove 19 of 20 stored entries, more than 10%. The previous data is kept. " \
                       "If the source really dropped them, import again with ALLOW_DROPS=19.")
    expect(panel("kev").css("#kev_import_list tbody tr").first.text.squish).to include("Held back")
    expect(facts(panel("kev").at_css("dl"))["Entries"]).to start_with("20 CVEs")
  end

  it "escapes every value from a feed: versions, sources, reasons, and problems" do
    evil = "<script>alert(1)</script>"
    SignalImport.create!(signal: "kev", origin: "file", source: evil, state: "succeeded", version: evil, counts: { "added" => 0, "removed" => 0, "in_file" => 0 },
                         started_at: Time.current, finished_at: Time.current)
    Signals.record_failure("epss", reason: evil, origin: "file", source: evil)
    get "/data-sources"
    expect(response.body).not_to include(evil)
    expect(panel("kev").at_css("#kev_freshness").text).to include("catalog version #{evil}")
    expect(panel("epss").at_css("#epss_import_list").text).to include("Nothing imported: #{evil}")
  end

  it "names KEV and EPSS in the freshness line on the fleet, Compliance, and host pages" do
    host = debian_host
    [ "/", "/compliance", "/hosts/#{host.id}/vulnerabilities" ].each do |path|
      get path
      expect(page.at_css("#signal_freshness").text.squish).to include("Known exploited (CISA KEV): not imported yet.", "Exploit prediction (FIRST EPSS): not imported yet."), path
    end
  end

  it "mentions the signals on the refresh confirmation and in the notice once it starts" do
    get "/data-sources/refresh"
    expect(page.at_css("#refresh_dialog").text.squish).to include("The exploitation signals (CISA KEV and FIRST EPSS) are refreshed after it too, each on its own.")
    post "/data-sources/refresh"
    follow_redirect!
    expect(page.text.squish).to include("The exploitation signals (CISA KEV, FIRST EPSS) are refreshed after it too.")
  end
end
