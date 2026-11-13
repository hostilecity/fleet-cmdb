require "rails_helper"

# Debian's triage in the dashboard (P2-D08, FR-2.4, FR-2.5, ADR 0022): the approved P2-D07 mockups host-vulns.html,
# host-vuln-package.html, host-vuln-package-libc6.html, data-sources.html, data-sources-stale.html,
# data-sources-held.html, and dialogs.html#refresh, with the owner's decisions T1 to T8 on #134. Triage is an
# annotation: no state, severity, filter other than the chip, or count changes because of it.
RSpec.describe "Debian's triage in the dashboard", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let(:start) { Time.utc(2026, 11, 7, 9, 0, 0) }
  let(:tracker) { "https://security-tracker.example.org/tracker/data/json" }
  let(:sample) { DebianTrackerHelpers::FIXTURES.join("sample.json") }

  around do |example|
    config = Advisories.config
    saved = config.to_h.slice(:feed_url, :feed_token, :refresh_cooldown)
    saved_tracker = DebianTriage.config.tracker_url
    config.feed_url = "https://feeds.example.lan/osv/Debian/all.zip"
    config.feed_token = nil
    config.refresh_cooldown = 300.seconds
    DebianTriage.config.tracker_url = tracker
    example.run
  ensure
    config.feed_url, config.feed_token, config.refresh_cooldown = saved.values_at(:feed_url, :feed_token, :refresh_cooldown)
    DebianTriage.config.tracker_url = saved_tracker
  end

  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later) # matching is run by hand, at known times
    allow(CisEvaluationJob).to receive(:perform_later)
    travel_to(start)
  end

  def match(*hosts) = VulnerabilityMatcher.match!(hosts.map(&:id))

  def facts(scope) = scope.css("dt").map { |dt| dt.text.squish }.zip(scope.css("dd").map { |dd| dd.text.squish }).to_h

  # One triage line: [what it says, the line under it], each squished.
  def line(node) = [ node.dup.tap { |n| n.css(".why").each(&:remove) }.text.squish, node.at_css(".why")&.text&.squish ]

  # The triage lines under each open advisory on the tab: { "package advisory" => [[text, why], ...] }.
  def tab_lines(table = "#open_list")
    page.css("#{table} tbody").each_with_object({}) do |body, lines|
      package = body.at_css("tr.pkg-group a").text.split(":").first
      body.css("tr.nested").each { |row| lines["#{package} #{row.css('td')[1].at_css('a, span.mono').text}"] = row.css(".triage").map { |node| line(node) } }
    end
  end

  # The owner's example (ADR 0022): CVE-2026-19499 in glibc, High by its CVSS score, no-DSA "Minor issue" for trixie.
  def glibc_example
    host = debian_host(name: "Media server", packages: [ [ "libc6", "2.41-12+deb13u4", "glibc" ] ])
    high = [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" } ]
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-19499", package: "glibc", fixed: nil, upstream: [ "CVE-2026-19499" ], severity: high,
                                 summary: "Example: buffer handling flaw in glibc."), full: true, origin: "feed")
    match(host)
    host
  end

  # Every kind of tracker entry for a trixie host, one source package each (host-vulns.html#triage-states).
  STATES = {
    "nodsa-npu" => { "nodsa" => "Minor issue", "nodsa_reason" => "", "next_point_update" => true },
    "nodsa" => { "nodsa" => "Minor issue" },
    "postponed" => { "nodsa" => "Minor issue", "nodsa_reason" => "postponed" },
    "ignored" => { "nodsa" => "Example: too intrusive to backport", "nodsa_reason" => "ignored" },
    "unimportant" => { "urgency" => "unimportant" },
    "urgent" => { "urgency" => "high" },
    "nodsa-low" => { "nodsa" => "Minor issue", "urgency" => "low" },
    "untriaged" => {},
    "undetermined" => { "status" => "undetermined" },
    "resolved" => { "status" => "resolved", "fixed_version" => "2.0-1" },
    "resolved-zero" => { "status" => "resolved", "fixed_version" => "0" }
  }.freeze

  def cve(index) = "CVE-2026-#{99_100 + index}"

  def state_catalogue
    names = STATES.keys + %w[no-entry no-cve named]
    host = debian_host(name: "Media server", packages: names.map { |name| [ "bin-#{name}", "1.0-1", "src-#{name}" ] })
    records = STATES.keys.each_with_index.map { |name, i| osv_record(id: "DEBIAN-#{cve(i)}", package: "src-#{name}", fixed: nil, database_specific: { "severity" => "medium" }) }
    records << osv_record(id: "DEBIAN-CVE-2026-99211", package: "src-no-entry", fixed: nil)
    records << osv_record(id: "DSA-9112-1", package: "src-no-cve", fixed: nil, database_specific: { "severity" => "high" })
    records << osv_record(id: "DSA-9113-1", package: "src-named", fixed: "1.0-2", upstream: [ "CVE-2026-99113", "CVE-2026-99114" ])
    import_advisories(*records, full: true, origin: "feed")
    match(host)
    document = STATES.each_with_index.to_h do |(name, extra), i|
      release = tracker_release(status: extra.fetch("status", "open"), urgency: extra.fetch("urgency", "not yet assigned"), **extra.except("status", "urgency").transform_keys(&:to_sym))
      [ "src-#{name}", { cve(i) => { "trixie" => release } } ]
    end
    document["src-named"] = { "CVE-2026-99113" => { "trixie" => tracker_release(urgency: "medium") } }
    [ host, tracker_document(document) ]
  end

  describe "the Vulnerabilities tab (host-vulns.html, T1, T3, T5, T7)" do
    it "shows the owner's example under the advisory, as Debian's note, with the severity, state, and counts unchanged" do
      host = glibc_example
      import_triage(sample)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(response).to have_http_status(:ok)
      expect(tab_lines).to eq("libc6 DEBIAN-CVE-2026-19499" => [ [ "Debian: no security update planned (Minor issue); fix planned for the next point release", nil ] ])
      row = page.at_css("#open_list tr.nested")
      expect(row.css("td").drop(2).map { |td| td.text.squish }).to eq([ "High", "No fix available", "Open", "2026-11-07 09:00 UTC → —" ])
      expect(row.at_css(".triage q").text).to eq("Minor issue")
      expect(row.at_css(".triage .lamp, .triage .sev")).to be_nil # no lamp and no severity colour (T1)
      expect(page.at_css("#open_heading").text.squish).to eq("Open findings 1: 1 high")
      expect(page.at_css("#advisory_freshness").text.squish).to eq("Advisory data last updated: Debian:13 less than 5 seconds ago. Debian's triage for trixie: less than 5 seconds ago. Data sources")
      expect(page.at_css("#triage_freshness a")["href"]).to eq("/data-sources#tracker")
      expect(page.at_css("#triage_legend").text.squish).to eq(
        "Debian: … lines are the Debian security team's own note for this host's release (trixie), from the Debian Security Tracker. They are shown beside the finding " \
        "and never change its severity, its state, or any count: a finding stays open until the installed version is outside the affected range."
      )
      expect(page.text).not_to include("Scope:", "1100001") # the scope is on the package page only, and the bug number nowhere (T6)
      expect(page.css("#open_list a[href*='security-tracker']")).to be_empty
    end

    it "shows every state of a tracker entry in our words, with Debian's note quoted (T7)" do
      host, document = state_catalogue
      import_triage(document)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(tab_lines).to eq(
        "bin-nodsa-npu DEBIAN-CVE-2026-99100" => [ [ "Debian: no security update planned (Minor issue); fix planned for the next point release", nil ] ],
        "bin-nodsa DEBIAN-CVE-2026-99101" => [ [ "Debian: no security update planned (Minor issue)", nil ] ],
        "bin-postponed DEBIAN-CVE-2026-99102" => [ [ "Debian: postponed to a later update or point release (Minor issue)", nil ] ],
        "bin-ignored DEBIAN-CVE-2026-99103" => [ [ "Debian: ignored, no fix planned for this release (Example: too intrusive to backport)", nil ] ],
        "bin-unimportant DEBIAN-CVE-2026-99104" => [ [ "Debian: unimportant", "Debian's urgency for this release. The installed version is still in the affected range." ] ],
        "bin-urgent DEBIAN-CVE-2026-99105" => [ [ "Debian: urgency high", nil ] ],
        "bin-nodsa-low DEBIAN-CVE-2026-99106" => [ [ "Debian: no security update planned (Minor issue), urgency low", nil ] ],
        "bin-untriaged DEBIAN-CVE-2026-99107" => [ [ "Debian: not triaged yet", nil ] ],
        "bin-undetermined DEBIAN-CVE-2026-99108" => [ [ "Debian: not yet determined for trixie", nil ] ],
        "bin-resolved DEBIAN-CVE-2026-99109" => [ [ "Debian: fixed for trixie in 2.0-1", "This host has 1.0-1, so the finding stays open." ] ],
        "bin-resolved-zero DEBIAN-CVE-2026-99110" => [ [ "Debian: marked resolved for trixie", "This host has 1.0-1; the finding stays open while the advisory data's affected range includes it." ] ],
        "bin-no-entry DEBIAN-CVE-2026-99211" => [ [ "Debian triage not available", "The tracker has no entry for CVE-2026-99211 in trixie." ] ],
        "bin-no-cve DSA-9112-1" => [ [ "Debian triage not available", "This advisory names no CVE, so there is nothing to look up." ] ],
        "bin-named DSA-9113-1" => [ [ "Debian: urgency medium", "For CVE-2026-99113." ], [ "Debian triage not available", "CVE-2026-99114: the tracker has no entry for it in trixie." ] ]
      )
      # Wording never says a finding is fixed or not affected because of Debian's triage (P2-D07), and every open row stays open.
      texts = page.css("#open_list .triage").map { |node| node.text.squish }
      expect(texts).to all(start_with("Debian"))
      expect(texts.grep(/not affected|unaffected|no longer|is fixed|safe/i)).to eq([])
      expect(page.css("#open_list tr.nested td:nth-child(5)").map { |td| td.text.squish }.uniq).to eq([ "Open" ])
      # The product says CIS-aligned, never CIS compliant (DEC-10).
      expect(page.at_css("#glance_cis, .glance").text).to include("CIS-aligned checks")
      expect(page.text.match?(/\bCIS[- ]complian(t|ce)\b|\bcomplian(t|ce) (with|to) (the )?CIS\b/i)).to be(false)
    end

    it "cuts Debian's note at 200 characters with an ellipsis, verbatim otherwise (T7)" do
      host, document = state_catalogue
      long = "#{'Example note. ' * 20}end"
      document["src-nodsa"]["CVE-2026-99101"]["releases"]["trixie"]["nodsa"] = long
      import_triage(document)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(page.at_css("#open_list tbody:has(a[href$='package=bin-nodsa']) q").text).to eq("#{long[0, 200]}…")
      document["src-nodsa"]["CVE-2026-99101"]["releases"]["trixie"]["nodsa"] = "Exactly as Debian says it: \"quoted\", <b>tags</b> & all"
      import_triage(document)
      get "/hosts/#{host.id}/vulnerabilities"
      note = page.at_css("#open_list tbody:has(a[href$='package=bin-nodsa']) q")
      expect([ note.text, note.children.map(&:name) ]).to eq([ "Exactly as Debian says it: \"quoted\", <b>tags</b> & all", [ "text" ] ])
    end

    it "shows a no-DSA note after a status that is not open, and counts only entries Debian has not resolved (review of #136)" do
      host, document = state_catalogue
      release = ->(name, index) { document["src-#{name}"][cve(index)]["releases"]["trixie"] }
      release.("undetermined", 8).merge!("nodsa" => "Example: needs triage", "nodsa_reason" => "ignored")
      release.("resolved", 9).merge!("nodsa" => "Minor issue")
      import_triage(document)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(tab_lines.values_at("bin-undetermined DEBIAN-CVE-2026-99108", "bin-resolved DEBIAN-CVE-2026-99109")).to eq([
        [ [ "Debian: not yet determined for trixie; ignored, no fix planned for this release (Example: needs triage)", nil ] ],
        [ [ "Debian: fixed for trixie in 2.0-1; no security update planned (Minor issue)", "This host has 1.0-1, so the finding stays open." ] ]
      ])
      expect(page.at_css("#triage_filter a").text.squish).to eq("Debian: no security update planned 6") # the undetermined one, not the resolved one

      get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "bin-resolved" }
      expect(page.at_css("#package_findings tbody tr td:nth-child(7) .triage .why").text.squish).to start_with("This host has 1.0-1, so the finding stays open.")
    end

    it "quotes Debian's note with its spaces and lines as written (review of #136)" do
      host, document = state_catalogue
      document["src-nodsa"]["CVE-2026-99101"]["releases"]["trixie"]["nodsa"] = "See  section A\nthen B"
      import_triage(document)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(page.at_css("#open_list tbody:has(a[href$='package=bin-nodsa']) q").text).to eq("See  section A\nthen B")
    end

    it "filters by 'Debian: no security update planned' on every no-DSA reason, keeping the other filters, counted within the state (T3)" do
      host, document = state_catalogue
      import_triage(document)
      get "/hosts/#{host.id}/vulnerabilities"
      chip = page.at_css("#triage_filter a")
      expect([ chip.text.squish, chip["aria-current"], chip["href"] ]).to eq([ "Debian: no security update planned 5", nil, "/hosts/#{host.id}/vulnerabilities?debian=no_dsa" ])
      expect(page.at_css("#triage_filter")["aria-label"]).to eq("Filter findings by Debian's triage: no-DSA, postponed, or ignored")

      get "/hosts/#{host.id}/vulnerabilities", params: { debian: "no_dsa" }
      expect(tab_lines.keys).to contain_exactly("bin-nodsa-npu DEBIAN-CVE-2026-99100", "bin-nodsa DEBIAN-CVE-2026-99101", "bin-postponed DEBIAN-CVE-2026-99102",
                                                "bin-ignored DEBIAN-CVE-2026-99103", "bin-nodsa-low DEBIAN-CVE-2026-99106")
      chip = page.at_css("#triage_filter a")
      expect([ chip["aria-current"], chip["href"] ]).to eq([ "true", "/hosts/#{host.id}/vulnerabilities" ]) # selected; selecting again clears it
      expect(page.at_css("#finding_filters input[name=debian]")["value"]).to eq("no_dsa")
      # The state chips' counts are unchanged.
      expect(page.css("#state_filters a").map { |a| a.text.squish }).to eq([ "Open and reopened 14", "Resolved 0", "All 14" ])

      # With a severity and a search: the list narrows, the chip's count stays within the state filter.
      get "/hosts/#{host.id}/vulnerabilities", params: { debian: "no_dsa", severity: "medium", q: "postponed" }
      expect(tab_lines.keys).to eq([ "bin-postponed DEBIAN-CVE-2026-99102" ])
      expect(page.at_css("#triage_filter a").text.squish).to eq("Debian: no security update planned 5")
      get "/hosts/#{host.id}/vulnerabilities", params: { debian: "no_dsa", severity: "high" }
      expect(page.at_css("#open_findings").text.squish).to include("No open findings match. Clear the filters")

      # Only on the open and reopened list, the rows that show the triage (T5).
      get "/hosts/#{host.id}/vulnerabilities", params: { debian: "no_dsa", state: "all" }
      expect(page.at_css("#triage_filter")).to be_nil
      expect(page.css("#open_list tbody").size).to eq(14)
    end

    it "shows the triage on open and reopened rows only; the package page shows it on every row, as today's note (T5)" do
      host, document = state_catalogue
      import_triage(document)
      report_packages(host, (STATES.keys + %w[no-entry no-cve named]).reject { |n| n == "resolved" }.map { |name| [ "bin-#{name}", "1.0-1", "src-#{name}" ] })
      match(host)
      get "/hosts/#{host.id}/vulnerabilities", params: { state: "all" }
      expect(page.css("#resolved_list tr.nested").size).to eq(1)
      expect(page.css("#resolved_list .triage")).to be_empty
      expect(page.css("#open_list .triage").size).to eq(14)

      get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "bin-resolved" }
      cell = page.at_css("#package_findings tbody tr td:nth-child(7)")
      expect(line(cell.at_css(".triage"))).to eq([ "Debian: fixed for trixie in 2.0-1", "Scope: remote. Debian's page for CVE-2026-99109" ])
      expect(cell.text).not_to include("stays open")
    end

    it "says Debian's triage is not available, and why, for a release outside the release table", triage_releases: { [ "debian", "12" ] => "bookworm" } do
      host = glibc_example
      import_triage(sample)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(tab_lines.values.flatten(1)).to eq([ [ "Debian triage not available", "This host's release (Debian 13) is not mapped to a tracker release yet." ] ])
      expect(page.at_css("#triage_freshness")).to be_nil
      expect(page.at_css("#triage_legend")).to be_nil
      get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "libc6" }
      expect(page.css("#package_findings th").map { |th| th.text.squish }).to include("Debian's triage")
      expect(facts(page.at_css("#installed_package"))).to include("Debian triage for" => "No release in the tracker's release table")
    end

    it "says the source is turned off, or not imported yet, in the freshness line and on each finding" do
      host = glibc_example
      get "/hosts/#{host.id}/vulnerabilities"
      expect(tab_lines.values.flatten(1)).to eq([ [ "Debian triage not available", "The tracker data has not been imported yet." ] ])
      expect(page.at_css("#triage_freshness").text.squish).to start_with("Debian's triage for trixie: not imported yet.")

      DebianTriage.config.tracker_url = nil
      get "/hosts/#{host.id}/vulnerabilities"
      expect(tab_lines.values.flatten(1)).to eq([ [ "Debian triage not available", "The Debian Security Tracker import is turned off on this server." ] ])
      expect(page.at_css("#triage_freshness").text.squish).to start_with("Debian's triage: turned off on this server.")
      expect(page.at_css("#triage_stale")).to be_nil

      import_triage(sample) # a file imported by hand while the refresh is off still counts
      get "/hosts/#{host.id}/vulnerabilities"
      expect(tab_lines.values.flatten(1).first.first).to start_with("Debian: no security update planned")
    end
  end

  describe "stale triage (T8)" do
    it "shows 'not available' with the last import date on each finding, and a notice on the Vulnerabilities tab only" do
      host = glibc_example
      import_triage(sample)
      travel 49.hours
      sign_in_operator # the session has expired
      high = [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" } ]
      import_advisories(osv_record(id: "DEBIAN-CVE-2026-19499", package: "glibc", fixed: nil, upstream: [ "CVE-2026-19499" ], severity: high, modified: "2026-11-01T00:00:00Z"),
                        full: true, origin: "feed")
      get "/hosts/#{host.id}/vulnerabilities"
      expect(tab_lines.values.flatten(1)).to eq([ [ "Debian triage not available", "The tracker data is older than 48 hours (last imported 2026-11-07 09:00 UTC)." ] ])
      notice = page.at_css("#triage_stale")
      expect([ notice["class"], notice["role"] ]).to eq([ "notice info", "status" ])
      expect(notice.text.squish).to eq("Debian's triage is out of date, so it is not shown. Tracker data for trixie was last imported 2 days ago (2026-11-07 09:00 UTC). " \
                                       "Findings, severity, and counts come from the advisory data and are not affected. See the data sources.")
      expect(page.at_css("#triage_stale a")["href"]).to eq("/data-sources#tracker")
      expect(page.at_css("#open_list tr.nested td:nth-child(3)").text.squish).to eq("High")
      expect(page.at_css("#state_filters a").text.squish).to eq("Open and reopened 1")

      get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "libc6" }
      expect(page.at_css("#triage_stale")).to be_nil
      expect(line(page.at_css("#package_findings .triage")).last).to eq("The tracker data is older than 48 hours (last imported 2026-11-07 09:00 UTC).")

      [ "/", "/compliance" ].each do |path|
        get path
        expect(response.body).not_to include("Debian's triage", "triage_stale"), path
      end

      get "/data-sources"
      expect(page.at_css("#tracker_freshness").text.squish).to eq("Out of date, so not shown beside findings. trixie last imported 2 days ago (2026-11-07 09:00 UTC).")
      expect(page.at_css("#tracker_releases tbody tr td:nth-child(2)").text.squish).to eq("Stale: older than 48 hours")
    ensure
      travel_back
    end
  end

  describe "the package page (host-vuln-package.html, host-vuln-package-libc6.html, T6)" do
    it "gives the triage its own column with the explanation, the CVE's scope, and the tracker's page, and no bug number" do
      host = glibc_example
      import_triage(sample)
      get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "libc6" }
      expect(page.css("#package_findings thead th").map { |th| th.text.squish })
        .to eq([ "Severity", "Advisory", "Package", "Installed then", "Fixed in", "State", "Debian's triage (trixie)", "History" ])
      cell = page.at_css("#package_findings tbody tr td:nth-child(7)")
      expect(line(cell.at_css(".triage"))).to eq([
        "Debian: no security update planned (Minor issue); fix planned for the next point release",
        "Debian's security team plans no security update (DSA) for this in trixie and expects the fix in the next trixie point release. " \
        "Until then the installed version is still in the affected range. Scope: remote. Debian's page for CVE-2026-19499"
      ])
      link = cell.at_css("a")
      expect([ link["href"], link["rel"], link["target"] ]).to eq([ "https://security-tracker.debian.org/tracker/CVE-2026-19499", "noopener noreferrer", "_blank" ])
      expect(page.css("#package_findings tbody tr td:nth-child(1)").map(&:text)).to eq([ "High" ])
      expect(response.body).not_to include("1100001") # Debian's bug number is not shown (T6)
      expect(facts(page.at_css("#installed_package"))).to include("Debian triage for" => "trixie (Debian 13)")
      expect(page.at_css("#package_summary").text.squish).to include(
        "The advisory data gives no fixed version for DEBIAN-CVE-2026-19499 in trixie yet; check the advisory's affected range for a version outside it. " \
        "Debian's note says a fix is planned for the next point release; " \
        "the finding resolves only when the installed version is outside the affected range."
      )
    end

    it "explains each state, names the CVE of a DSA, and links only entries the tracker has" do
      host, document = state_catalogue
      import_triage(document)
      cell = ->(package) do
        get "/hosts/#{host.id}/vulnerabilities/package", params: { package: }
        page.css("#package_findings tbody tr td:nth-child(7) .triage").map { |node| line(node) }
      end
      expect(cell.("bin-postponed")).to eq([ [ "Debian: postponed to a later update or point release (Minor issue)",
                                               "Debian's security team has postponed the fix for this in trixie to a later update or point release. " \
                                               "The installed version is still in the affected range. Scope: remote. Debian's page for CVE-2026-99102" ] ])
      expect(cell.("bin-ignored").sole.last).to start_with("Debian's security team does not plan to fix this in trixie.")
      expect(cell.("bin-unimportant")).to eq([ [ "Debian: unimportant", "Debian's urgency for trixie; it does not say the package is unaffected. Scope: remote. Debian's page for CVE-2026-99104" ] ])
      expect(cell.("bin-named")).to eq([ [ "Debian: urgency medium", "CVE-2026-99113. Scope: remote. Debian's page for CVE-2026-99113" ],
                                         [ "Debian triage not available", "CVE-2026-99114: the tracker has no entry for it in trixie." ] ])
      expect(page.css("#package_findings a[href*='security-tracker']").map { |a| a["href"] }).to eq([ "https://security-tracker.debian.org/tracker/CVE-2026-99113" ])
      expect(cell.("bin-no-cve")).to eq([ [ "Debian triage not available", "DSA-9112-1 names no CVE, so there is nothing to look up." ] ])
      expect(page.css("#package_findings a[href*='security-tracker']")).to be_empty
    end
  end

  describe "the data sources page (data-sources.html#tracker, data-sources-held.html, T2, T4)" do
    it "shows the tracker as a second source, triage only, with its freshness, entry counts, hosts, next refresh, and imports, and links the docs (#148)" do
      glibc_example
      import_triage(sample)
      get "/data-sources"
      panel = page.at_css("#tracker")
      expect(panel.at_css("h2").text.squish).to eq("Debian Security Tracker Triage only")
      expect(panel.at_css("h2 + p").text.squish).to eq("Debian's own triage, shown beside findings. Never changes a finding's state, severity, or count.")
      expect(page.at_css("#triage_freshness").text.squish).to eq("Debian's triage for trixie: less than 5 seconds ago.")
      expect(panel.css("#tracker_releases tbody tr td").map { |td| td.text.squish }).to eq([
        "trixieDebian 13, Debian:13", "Fresh", "2026-11-07 09:00 UTC less than 5 seconds ago", "3 entries1 open1 no-DSA, 0 postponed, 0 ignored", "1 host"
      ])
      # The split by no-DSA reason is a closed disclosure, reachable by keyboard and touch (review of #173).
      split = panel.at_css("#tracker_releases td:nth-child(4) details")
      expect([ split["open"], split.at_css("summary").text, split.at_css("p").text ]).to eq([ nil, "1 open", "1 no-DSA, 0 postponed, 0 ignored" ])
      expect(panel.at_css("#tracker_releases a")["href"]).to eq("/compliance?ecosystem=Debian%3A13")
      expect(panel.at_css("#tracker_schedule").text.squish)
        .to eq("From security-tracker.example.org/tracker/data/json. Not scheduled in this environment; Refresh now above refreshes it too.")
      expect(panel.css("form, input[type=file], button")).to be_empty # no upload and no button of its own (T2)
      expect(panel.css("#tracker_import_list tbody tr td").map { |td| td.text.squish })
        .to eq([ "2026-11-07 09:00", "File import on the server", "Succeeded", "bookworm: 1 kept; forky: 1 kept; sid: 1 kept; trixie: 3 kept; 5 entries read; 3 malformed", "System" ])
      expect(panel.at_css("#tracker_held, #tracker_freshness, #tracker_off")).to be_nil
      expect(panel.css(".pager span").map { |span| span.text.squish }).to eq([ "Showing the latest 1 import.", "Every import, with its counts per release, is in the audit log." ])
      expect(panel.at_css("#tracker_docs").text.squish)
        .to eq(%(How Debian triage works, its limits, and importing without internet access: docs/operations/health-and-jobs.md, "Debian triage".))
      # The explanations moved to the docs (#148).
      expect(panel.text.squish).not_to include("Scheduled download", "No upload", "ETag", "MiB", "config/triage_releases.yml", "FLEET_DEBIAN_TRACKER_URL")
    end

    it "shows a held-back import with its counts and a status notice, on this page only, with no button to accept it (T4)" do
      host = glibc_example
      import_triage(sample)
      travel 1.hour
      import_triage({ "glibc" => {} }, origin: "feed", source: "security-tracker.example.org/tracker/data/json")
      get "/data-sources"
      notice = page.at_css("#tracker_held")
      expect([ notice["class"], notice["role"] ]).to eq([ "notice", "status" ])
      expect(notice.text.squish).to eq(
        "The last refresh was held back. It would have removed 100% of bookworm's entries, 100% of forky's entries, 100% of sid's entries, " \
        "and 100% of trixie's entries; the previous data is kept."
      )
      expect(page.at_css("#tracker_releases tbody tr td:nth-child(2)").text.squish).to eq("Fresh Last refresh held back")
      held = page.at_css("#tracker_import_list tbody tr")
      expect(held.css("td").map { |td| td.text.squish }.values_at(1, 2, 3)).to eq([
        "Scheduled refresh", "Held back", "bookworm: held back (1 of 1 would be removed); forky: held back (1 of 1 would be removed); " \
                                          "sid: held back (1 of 1 would be removed); trixie: held back (3 of 3 would be removed); 0 entries read"
      ])
      expect(page.css("#tracker form, #tracker button")).to be_empty

      get "/hosts/#{host.id}/vulnerabilities"
      expect(page.at_css("#tracker_held, #triage_stale")).to be_nil
      expect(tab_lines.values.flatten(1).first.first).to start_with("Debian: no security update planned") # the kept data is still shown

      # Once the kept data is stale it is no longer shown, and the notice says so (review of #136).
      travel 2.days
      sign_in_operator # the session expired meanwhile
      get "/data-sources"
      expect(page.at_css("#tracker_held").text.squish).to end_with(
        "the previous data is kept. The previous data for trixie is out of date, so it is no longer shown beside findings."
      )
      expect(page.at_css("#tracker_freshness")).to be_nil # the held-back notice says it, once
    ensure
      travel_back
    end

    it "says the refresh is off when no tracker is configured" do
      glibc_example
      DebianTriage.config.tracker_url = nil
      get "/data-sources"
      expect(page.at_css("#tracker_off").text.squish).to eq("Turned off on this server. Its data changes only when a file is imported on the server.")
      expect(page.at_css("#tracker_schedule")).to be_nil
      expect(page.at_css("#no_tracker_imports").text.squish).to eq("Nothing imported yet.")
    end

    it "says why nothing was imported when no active host uses a release in the release table (#148)" do
      DebianTriage::Import.new(origin: "feed", source: "security-tracker.example.org/tracker/data/json").call(nil)
      DebianTriage::Import.new(origin: "file", source: "json").call(nil)
      get "/data-sources"
      expect(page.css("#tracker_import_list tbody tr").map { |tr| tr.css("td").map { |td| td.text.squish }.values_at(1, 3) }).to eq([
        [ "File import on the server", "Nothing imported: no active host uses a release in the release table" ],
        [ "Scheduled refresh", "Nothing downloaded: no active host uses a release in the release table" ]
      ])
      expect(page.at_css("#tracker_releases tbody td").text.squish).to eq("No active host uses a release in the release table yet.")
    end

    it "says in one notice which release is out of date and how many refreshes failed, and only removed counts above zero (#148)" do
      glibc_example
      hosts_on("12") # bookworm, never imported
      import_triage(sample, releases: [ "trixie" ])
      travel 1.hour
      smaller = tracker_document("glibc" => { "CVE-2026-19499" => { "trixie" => tracker_release(nodsa: "Minor issue") } })
      import_triage(smaller, releases: [ "trixie" ], allowed_drops: { "trixie" => 2 })
      travel 2.days + 1.hour
      2.times { DebianTriage::Import.record_failure(reason: "the tracker answered HTTP 503", origin: "feed", source: "security-tracker.example.org/tracker/data/json") }
      sign_in_operator # the session expired meanwhile
      get "/data-sources"
      notice = page.at_css("#tracker_freshness")
      expect(notice.text.squish).to eq("Out of date, so not shown beside findings. bookworm not imported yet; trixie last imported 2 days ago (2026-11-07 10:00 UTC). " \
                                       "The last 2 refreshes failed (see the failed jobs).")
      expect(notice.at_css("a")["href"]).to eq("/jobs/failed")
      expect(page.css("#tracker_import_list tbody tr td:nth-child(4)").map { |td| td.text.squish }.last(2)).to eq([
        "trixie: 1 kept, 2 removed; 1 entry read", "trixie: 3 kept; 5 entries read; 2 malformed"
      ])
    ensure
      travel_back
    end

    it "says when the next scheduled refresh runs, in one line with the source (#148)" do
      glibc_example
      allow(TriageDataSources).to receive(:recurring_jobs).and_return(YAML.safe_load_file(Rails.root.join("config/recurring.yml")).fetch("production"))
      allow(TriageDataSources).to receive(:next_refresh).and_return(start + 4.hours) # its time zone is the model spec's
      get "/data-sources"
      expect(page.at_css("#tracker_schedule").text.squish).to eq(
        "From security-tracker.example.org/tracker/data/json. Next refresh in about 4 hours (every 6 hours, after the advisory feed); Refresh now above refreshes it too."
      )
    end

    it "says in the refresh confirmation, in one sentence, that Debian's triage is refreshed right after, and attributes it to the operator (T2)" do
      get "/data-sources/refresh"
      sentence = "Debian's triage data (the Debian Security Tracker) is refreshed right after it; if that fails, the advisory data is still imported."
      expect(page.at_css("#refresh_dialog p").text.squish).to end_with(sentence)
      post "/data-sources/refresh"
      expect(flash[:notice]).to end_with("Debian's triage is refreshed right after it.")
      expect(AdvisoryFeedRefreshJob).to have_been_enqueued.with(attempt_id: AdvisoryRefreshAttempt.sole.id, triage: true)

      TriageImport.create!(tracker: "debian", origin: "feed", source: "security-tracker.example.org/tracker/data/json", operator:, state: "failed",
                           reason: "the Debian Security Tracker at security-tracker.example.org answered HTTP 503", started_at: Time.current, finished_at: Time.current)
      get "/data-sources"
      expect(page.css("#tracker_import_list tbody tr td").map { |td| td.text.squish }.values_at(1, 2, 3, 4)).to eq([
        "Refresh now, after the advisory feed", "Failed", "Nothing imported: the Debian Security Tracker at security-tracker.example.org answered HTTP 503", operator.display_name
      ])

      DebianTriage.config.tracker_url = nil
      travel 10.minutes do
        get "/data-sources/refresh"
        expect(page.at_css("#refresh_dialog p").text).not_to include("Debian's triage")
      end
    end
  end

  describe "counts (ADR 0022, item 3)" do
    it "leaves the compliance page, the fleet list, and the tab's counts, severities, and states identical with and without triage data" do
      host, document = state_catalogue
      other = debian_host(name: "Other", hostname: "vm-02.example.lan", packages: [ [ "bin-nodsa", "1.0-1", "src-nodsa" ] ])
      match(other)
      snapshot = lambda do
        get "/compliance"
        compliance = page.at_css("main").text.squish
        get "/"
        fleet = page.at_css("main").text.squish
        get "/hosts/#{host.id}/vulnerabilities", params: { state: "all" }
        tab = [ page.css("#state_filters a").map { |a| a.text.squish }, page.at_css("#open_heading").text.squish, page.at_css("#glance_vulns").text.squish,
                page.css("nav.tabs a").map { |a| a.text.squish }, page.css("#open_list tr").map { |tr| tr.css("td").drop(2).map { |td| td.text.squish } } ]
        get "/hosts/#{host.id}/vulnerabilities", params: { severity: "medium" }
        filtered = page.css("#open_list tr.nested").size
        [ compliance, fleet, tab, filtered ]
      end
      get "/" # past the sign-in notice
      without = snapshot.call
      import_triage(document)
      with = snapshot.call
      expect(with).to eq(without)
      expect(with[2].first).to eq([ "Open and reopened 14", "Resolved 0", "All 14" ])
      expect(page.css("#open_list .triage")).not_to be_empty # the triage is there, and changed nothing
    end
  end

  # The tab and the package page stay within their query bound plus the triage lookup, whatever the number of
  # findings (P2-D08 acceptance: measured at a host with 500 findings). Before P2-D08 both took 24 queries at 500
  # findings; the triage adds the host release's freshness and FindingTriage (inventories, freshness, entries;
  # the advisories are loaded already), and the chip's count reloads the open findings when a filter is set. The
  # host summary counts the host's open tasks for the Tasks tab (P3-DASH-TASKS): one query.
  it "renders the tab and the package page for a host with 500 findings in a fixed number of queries" do
    packages = (1..50).flat_map { |i| [ [ "acme#{i}", "1.0-1", "src#{i}" ], [ "libacme#{i}", "1.0-1", "src#{i}" ] ] }
    large = debian_host(packages:)
    small = debian_host(name: "Small", hostname: "vm-02.example.lan", packages: [ [ "acme1", "1.0-1", "src1" ] ])
    records = (1..50).flat_map { |i| (1..5).map { |j| osv_record(id: "DEBIAN-CVE-2026-#{10_000 + (i * 10) + j}", package: "src#{i}", fixed: nil) } }
    import_advisories(*records, full: true, origin: "feed")
    match(large, small)
    reasons = [ {}, { "nodsa" => "Minor issue" }, { "nodsa" => "Minor issue", "nodsa_reason" => "postponed" }, { "urgency" => "low" } ]
    import_triage(tracker_document((1..50).to_h do |i|
      [ "src#{i}", (1..4).to_h { |j| [ "CVE-2026-#{10_000 + (i * 10) + j}", { "trixie" => tracker_release(**reasons[j - 1].transform_keys(&:to_sym)) } ] } ]
    end))
    expect(VulnerabilityFinding.where(host: large).count).to eq(500)

    tab = ->(host, **params) { count_queries { get "/hosts/#{host.id}/vulnerabilities", params: } }
    tab.call(large) # warm up
    expect(page.css("#open_list .triage").size).to eq(500)
    expect(page.at_css("#triage_filter a").text.squish).to eq("Debian: no security update planned 200")
    queries = tab.call(large)
    expect(queries).to eq(tab.call(small))
    expect(queries).to be <= 24 + 5
    filtered = tab.call(large, severity: "unknown", debian: "no_dsa")
    expect(filtered).to eq(tab.call(small, severity: "unknown", debian: "no_dsa"))
    expect(filtered).to be <= queries + 2 # the open findings again, for the chip's count
    timings = Array.new(3) { Process.clock_gettime(Process::CLOCK_MONOTONIC).then { |t0| get("/hosts/#{large.id}/vulnerabilities") && Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0 } }
    expect(timings.min).to be < 2

    package = ->(host) { count_queries { get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "acme1" } } }
    expect(package.call(large)).to eq(package.call(small))
    expect(package.call(large)).to be <= 24 + 5
    puts format("\n  500 findings: tab %d queries, %.0f ms (best of 3); package page %d queries", queries, timings.min * 1000, package.call(large)) if ENV["SHOW_TIMINGS"]
  end
end
