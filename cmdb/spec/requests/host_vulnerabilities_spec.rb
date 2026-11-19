require "rails_helper"

# The Vulnerabilities tab and one package's findings (P2-D04, FR-2.4, FR-2.5; approved mockups host-vulns.html,
# host-vuln-package.html, states-packages-vulns.html).
RSpec.describe "Host vulnerabilities", :signed_in, type: :request do
  let(:start) { Time.utc(2026, 11, 6, 9, 0, 0) }

  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later) # matching is run by hand, at known times
    allow(CisEvaluationJob).to receive(:perform_later)
    travel_to(start)
  end

  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  def match(host, at: Time.current) = VulnerabilityMatcher.match!([ host.id ], now: at)

  def advisory(id, package, severity: "high", fixed: "2.0-1", url: "https://security.example.lan/advisories/#{id}", **extra)
    osv_record(id:, package:, fixed:, summary: "Example: a flaw in #{package}.", database_specific: { "severity" => severity },
               references: url ? [ { "type" => "ADVISORY", "url" => url } ] : [], **extra)
  end

  # A cell's words without Debian's triage lines (P2-D08), which spec/requests/debian_triage_views_spec.rb covers.
  def cell_words(td) = words(td.dup.tap { |cell| cell.css(".triage").each(&:remove) })

  # [package row, [advisory rows]] for each group of a findings table; the advisories are in the group's disclosure.
  def groups(table) = page.css("##{table} > tbody").map { |body| [ words(body.at_css("tr.pkg-group")), body.css("table.nested-findings tbody tr").map { |row| row.css("td").map { |td| cell_words(td) } } ] }

  # The package page's rows, without the Debian's triage column (P2-D08).
  def package_rows = page.css("#package_findings tbody tr").map { |row| row.css("td").map { |td| cell_words(td) }.tap { |cells| cells.delete_at(6) } }

  describe "an evaluated host" do
    let!(:host) do
      debian_host(name: "Media server", packages: [ [ "acme-daemon", "1.0-1", "acme" ], [ "libacme1", "1.0-1", "acme" ], [ "bash", "5.2.37-1", "bash" ],
                                                     [ "acme-docs", "1.0-1", "acme-docs", "all" ] ])
    end

    before do
      import_advisories(advisory("DSA-9100-1", "acme", severity: "high"), advisory("DSA-9101-1", "acme", severity: "low", fixed: nil),
                        advisory("DSA-9102-1", "acme-docs", severity: "medium", url: nil), full: true)
      match(host)
    end

    it "groups findings by package, one row each with its count, severity, fixes, and states, its advisories collapsed (Q16)" do
      get "/hosts/#{host.id}/vulnerabilities"
      expect(response).to have_http_status(:ok)
      expect(words(page.at_css("#open_heading"))).to eq("Open findings 5: 2 high, 1 medium, 2 low")
      expect(groups("open_list")).to eq([
        [ "acme-daemon:amd64 installed 1.0-1 2 advisories High 1 high, 1 low Fix for 1 of 2 2 open 2026-11-06 09:00 UTC", [
          [ "DSA-9100-1 Example: a flaw in acme.", "High", "Fixed in 2.0-1", "Open", "2026-11-06 09:00 UTC → —" ],
          [ "DSA-9101-1 Example: a flaw in acme.", "Low", "No fix available", "Open", "2026-11-06 09:00 UTC → —" ] ] ],
        [ "libacme1:amd64 installed 1.0-1 2 advisories High 1 high, 1 low Fix for 1 of 2 2 open 2026-11-06 09:00 UTC", [
          [ "DSA-9100-1 Example: a flaw in acme.", "High", "Fixed in 2.0-1", "Open", "2026-11-06 09:00 UTC → —" ],
          [ "DSA-9101-1 Example: a flaw in acme.", "Low", "No fix available", "Open", "2026-11-06 09:00 UTC → —" ] ] ],
        [ "acme-docs:all installed 1.0-1 1 advisory Medium 1 medium Fix available 1 open 2026-11-06 09:00 UTC", [
          [ "DSA-9102-1 No link recorded Example: a flaw in acme-docs.", "Medium", "Fixed in 2.0-1", "Open", "2026-11-06 09:00 UTC → —" ] ] ]
      ])
      link = page.at_css("#open_list a[href^='https://']")
      expect([ link.text, link["href"], link["rel"], link["target"] ]).to eq([ "DSA-9100-1", "https://security.example.lan/advisories/DSA-9100-1", "noopener noreferrer", "_blank" ])
      expect(page.at_css("#open_list tr.pkg-group a")["href"]).to eq("/hosts/#{host.id}/vulnerabilities/package?package=acme-daemon")
      expect(page.at_css("#resolved_findings")).to be_nil
      expect(page.css("nav.tabs a").map { |a| words(a) }.grep(/\AVulnerabilities/).sole).to eq("Vulnerabilities 5 open")
      expect(words(page.at_css("#glance_vulns"))).to eq("Open vulnerabilities 5 2 high, 1 medium, 2 low")
      expect(page.at_css("#glance_vulns")["href"]).to eq("/hosts/#{host.id}/vulnerabilities")
      expect(page.at_css("#advisory_freshness").text.squish).to start_with("Advisory data last updated: Debian:13")
    end

    it "filters by severity on single advisories, and by state and text, keeping the filters in the URL" do
      get "/hosts/#{host.id}/vulnerabilities", params: { severity: "low" }
      expect(groups("open_list").map(&:first)).to eq([ "acme-daemon:amd64 installed 1.0-1 1 advisory Low 1 low No fix available 1 open 2026-11-06 09:00 UTC", "libacme1:amd64 installed 1.0-1 1 advisory Low 1 low No fix available 1 open 2026-11-06 09:00 UTC" ])
      expect(page.at_css("#finding_filters select[name=severity] option[selected]")["value"]).to eq("low")
      get "/hosts/#{host.id}/vulnerabilities", params: { q: "dsa-9102" }
      expect(groups("open_list").map(&:first)).to eq([ "acme-docs:all installed 1.0-1 1 advisory Medium 1 medium Fix available 1 open 2026-11-06 09:00 UTC" ])
      get "/hosts/#{host.id}/vulnerabilities", params: { q: "libacme", severity: "critical" }
      expect(page.at_css("#open_findings").text.squish).to include("No open findings match. Clear the filters")
      get "/hosts/#{host.id}/vulnerabilities", params: { state: "resolved", severity: "high" }
      expect(page.at_css("#open_findings")).to be_nil
      expect(page.at_css("#resolved_findings").text.squish).to include("Resolved findings 0 No resolved findings match.")
      expect(page.css("#state_filters a").map { |a| [ words(a), a["aria-current"] ] }).to eq([ [ "Open and reopened 5", nil ], [ "Resolved 0", "true" ], [ "All 5", nil ] ])
      expect(Rack::Utils.parse_query(URI(page.at_css("#state_filters a")["href"]).query)).to eq("severity" => "high")
      get "/hosts/#{host.id}/vulnerabilities", params: { state: "bogus", severity: "bogus" }
      expect(page.at_css("#state_filters a[aria-current]").text).to start_with("Open and reopened")
    end

    it "shows when and how a finding resolved: fixed by an upgrade, removed, withdrawn, and reopened by a downgrade" do
      travel_to(start + 1.hour) { report_packages(host, [ [ "acme-daemon", "2.0-1", "acme" ], [ "libacme1", "1.0-1", "acme" ], [ "bash", "5.2.37-1", "bash" ] ]) }
      match(host, at: start + 1.hour)
      travel_to(start + 2.hours) { import_advisories(advisory("DSA-9101-1", "acme", severity: "low", fixed: nil, modified: "2026-11-01T00:00:00Z", withdrawn: "2026-11-01T00:00:00Z")) }
      match(host, at: start + 2.hours)
      travel_to(start + 3.hours) { report_packages(host, [ [ "acme-daemon", "1.0-1", "acme" ], [ "libacme1", "1.0-1", "acme" ], [ "bash", "5.2.37-1", "bash" ] ]) }
      match(host, at: start + 3.hours)
      get "/hosts/#{host.id}/vulnerabilities", params: { state: "all" }
      expect(groups("resolved_list")).to eq([ # by worst severity; each resolved finding keeps the version installed when it resolved
        [ "acme-docs:all installed 1.0-1 1 advisory Medium 1 medium Fix available 1 resolved 2026-11-06 09:00 UTC", [
          [ "DSA-9102-1 No link recorded Example: a flaw in acme-docs.", "Medium", "Fixed in 2.0-1", "Resolved Removed: package no longer installed", "2026-11-06 09:00 UTC → 2026-11-06 10:00 UTC" ] ] ],
        [ "acme-daemon:amd64 installed 2.0-1 1 advisory Low 1 low No fix available 1 resolved 2026-11-06 09:00 UTC", [
          [ "DSA-9101-1 Example: a flaw in acme.", "Low", "No fix available", "Resolved Withdrawn: the advisory was withdrawn by its source", "2026-11-06 09:00 UTC → 2026-11-06 11:00 UTC" ] ] ],
        [ "libacme1:amd64 installed 1.0-1 1 advisory Low 1 low No fix available 1 resolved 2026-11-06 09:00 UTC", [
          [ "DSA-9101-1 Example: a flaw in acme.", "Low", "No fix available", "Resolved Withdrawn: the advisory was withdrawn by its source", "2026-11-06 09:00 UTC → 2026-11-06 11:00 UTC" ] ] ]
      ])
      reopened = groups("open_list").first
      expect(reopened.first).to eq("acme-daemon:amd64 installed 1.0-1 1 advisory High 1 high Fix available 1 reopened 2026-11-06 09:00 UTC")
      expect(reopened.last.first.drop(3)).to eq([ "Reopened", "2026-11-06 09:00 UTC → Resolved 2026-11-06 10:00 UTC, reopened 2026-11-06 12:00 UTC" ])
      expect(words(page.at_css("#resolved_list_pager"))).to eq("3 packages, worst first: the most critical findings, then high, medium, low, and unknown, then the most with a fix.")

      get "/hosts/#{host.id}/vulnerabilities/package?package=acme-daemon"
      rows = package_rows
      expect(rows).to eq([
        [ "High", "DSA-9100-1 Example: a flaw in acme.", "acme-daemon:amd64", "1.0-1", "2.0-1", "Reopened",
          "2026-11-06 09:00 UTC first seen 2026-11-06 10:00 UTC resolved 2026-11-06 12:00 UTC reopened" ],
        [ "Low", "DSA-9101-1 Example: a flaw in acme.", "acme-daemon:amd64", "2.0-1", "No fix available", "Resolved Withdrawn: the advisory was withdrawn by its source",
          "2026-11-06 09:00 UTC first seen 2026-11-06 11:00 UTC resolved: withdrawn: the advisory was withdrawn by its source" ]
      ])
      expect(page.at_css("#package_summary").text.squish).to start_with("Findings for this package 1 open (1 reopened), 1 resolved.")
      expect(page.at_css("#package_summary").text.squish).to include("the affected range the installed version is in is fixed in 2.0-1. Check the advisory for any other affected range before relying on a later version.")
      expect(page.at_css("#package_summary").text).not_to include("or later resolves it")
      expect(page.at_css("#package_summary a")["href"]).to eq("/hosts/#{host.id}/vulnerabilities/package?package=libacme1")
      expect(page.at_css("title").text).to eq("Media server: findings for acme-daemon · Fleet CMDB")
    end

    it "shows one package: what is installed, and a package no longer installed" do
      get "/hosts/#{host.id}/vulnerabilities/package?package=acme-docs"
      expect(words(page.at_css("#installed_package"))).to eq("Installed package Name acme-docs:all Version 1.0-1 Source package acme-docs Package manager dpkg Ecosystem Debian:13 Debian triage for trixie (Debian 13)")
      report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ])
      match(host)
      get "/hosts/#{host.id}/vulnerabilities/package?package=acme-docs"
      expect(page.at_css("#installed_package").text).to include("Not installed now.")
      get "/hosts/#{host.id}/vulnerabilities/package?package=bash"
      expect(page.at_css("#package_summary").text.squish).to include("No findings.")
      expect(page.at_css("#package_findings")).to be_nil
      get "/hosts/#{host.id}/vulnerabilities/package?package=no-such-package.1"
      expect(response).to have_http_status(:not_found)
    end

    it "links the Packages tab's open findings to the package's findings" do
      get "/hosts/#{host.id}/packages", params: { findings: "open" }
      expect(page.css("#package_list td:last-child a").map { |a| [ a.text, a["href"] ] }.first).to eq([ "2 open", "/hosts/#{host.id}/vulnerabilities/package?package=acme-daemon" ])
    end

    it "lists packages it could not check" do
      report_packages(host, [ [ "acme-daemon", "1.0-1", "acme" ], [ "weird", "x:1", "acme" ] ])
      match(host)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#unchecked_packages"))).to start_with("2 package and advisory pairs could not be checked.")
      expect(page.css("#unchecked_list tbody tr").first.css("td").first(3).map { |td| words(td) }).to eq([ "weird:amd64", "x:1", "DSA-9100-1" ])
    end
  end

  describe "package groups, biggest offenders first (owner request: an actionable tab)" do
    let!(:host) do
      debian_host(name: "Media server", packages: [ [ "kernel", "1.0-1", "kernel" ], [ "ssl", "1.0-1", "ssl" ], [ "curl", "1.0-1", "curl" ], [ "xml", "1.0-1", "xml" ],
                                                     [ "zlib", "1.0-1", "zlib" ] ])
    end

    before do
      kernel = Array.new(5) { |i| advisory("DEBIAN-CVE-2026-#{1000 + i}", "kernel", severity: "high", fixed: (i < 2 ? "2.0-1" : nil)) }
      import_advisories(*kernel, advisory("DSA-9200-1", "ssl", severity: "critical", fixed: nil),
                        advisory("DSA-9201-1", "curl", severity: "medium"), advisory("DSA-9202-1", "curl", severity: "medium"),
                        advisory("DSA-9203-1", "xml", severity: "medium", fixed: nil), advisory("DSA-9204-1", "xml", severity: "medium", fixed: nil),
                        advisory("DSA-9205-1", "zlib", severity: "medium"), advisory("DSA-9206-1", "zlib", severity: "medium", fixed: nil), full: true)
      match(host)
    end

    def rows = page.css("#open_list > tbody > tr.pkg-group").map { |row| words(row) }

    it "ranks by the severity counts, critical first, then by how many have a fix, then by name, and says how many have a fix" do
      get "/hosts/#{host.id}/vulnerabilities"
      at = "2026-11-06 09:00 UTC"
      expect(rows).to eq([
        "ssl:amd64 installed 1.0-1 1 advisory Critical 1 critical No fix available 1 open #{at}", # one critical outranks five high
        "kernel:amd64 installed 1.0-1 5 advisories High 5 high Fix for 2 of 5 5 open #{at}",
        "curl:amd64 installed 1.0-1 2 advisories Medium 2 medium Fix for all 2 2 open #{at}", # as many medium: the most with a fix first
        "zlib:amd64 installed 1.0-1 2 advisories Medium 2 medium Fix for 1 of 2 2 open #{at}",
        "xml:amd64 installed 1.0-1 2 advisories Medium 2 medium No fix for any of 2 2 open #{at}"
      ])
      expect(page.at_css("#open_list tbody td .unavailable").text).to eq("No fix available")
      expect(words(page.at_css("#open_heading"))).to eq("Open findings 12: 1 critical, 5 high, 6 medium")
      expect(words(page.at_css("#open_list_pager"))).to start_with("5 packages, worst first")
      get "/hosts/#{host.id}/vulnerabilities", params: { severity: "medium" } # ranks the findings the filters keep
      expect(rows.map { |row| row.split.first }).to eq(%w[curl:amd64 zlib:amd64 xml:amd64])
    end

    it "collapses each package's advisories in a labelled native disclosure, opened by a text search" do
      get "/hosts/#{host.id}/vulnerabilities"
      details = page.css("#open_list details.advisories")
      expect(details.size).to eq(5)
      expect(details.map { |d| d.key?("open") }.uniq).to eq([ false ])
      kernel = page.at_css("#open_list > tbody:has(a[href$='package=kernel'])")
      summary = kernel.at_css("details summary")
      expect([ summary.at_css(".when-closed").text, summary.at_css(".when-open").text, summary.at_css(".visually-hidden").text ])
        .to eq([ "Show the 5 advisories", "Hide the 5 advisories", " for kernel:amd64" ])
      expect(kernel.at_css("details table caption").text).to eq("Advisories for kernel:amd64")
      expect(kernel.css("details table tbody tr").size).to eq(5)
      expect(kernel.at_css("details")["id"]).to eq("open_list_#{Digest::SHA256.hexdigest('kernel:amd64').first(16)}") # stable, so a morph pairs it
      expect(page.at_css("#open_list")["data-action"]).to eq("turbo:before-morph-attribute->keep-open#protect")
      expect(details.map { |d| d["id"] }.uniq.size).to eq(5)
      get "/hosts/#{host.id}/vulnerabilities", params: { q: "DSA-9201" }
      expect(page.css("#open_list details.advisories").map { |d| d.key?("open") }).to eq([ true ])
    end

    it "pages packages by keyset, with a cursor of its own for each section" do
      stub_const("HostFindingGroups::PER_PAGE", 2)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(rows.map { |row| row.split.first }).to eq(%w[ssl:amd64 kernel:amd64])
      pager = page.at_css("nav#open_list_pager")
      expect([ pager["aria-label"], words(pager.at_css(".muted")), pager.at_css(".off").text ]).to eq([ "Open finding pages", "2 packages shown of 5. Worst first.", "Previous" ])
      get pager.at_css("a[rel=next]")["href"]
      expect(rows.map { |row| row.split.first }).to eq(%w[curl:amd64 zlib:amd64])
      expect(Rack::Utils.parse_query(URI(page.at_css("#open_list_pager a[rel=next]")["href"]).query)).to eq("after" => "zlib:amd64")
      get page.at_css("#open_list_pager a[rel=next]")["href"]
      expect(rows.map { |row| row.split.first }).to eq(%w[xml:amd64])
      expect(page.at_css("#open_list_pager a[rel=next]")).to be_nil
      get page.at_css("#open_list_pager a[rel=prev]")["href"]
      expect(rows.map { |row| row.split.first }).to eq(%w[curl:amd64 zlib:amd64])
      get page.at_css("#open_list_pager a[rel=prev]")["href"] # back to the first page, full
      expect(rows.map { |row| row.split.first }).to eq(%w[ssl:amd64 kernel:amd64])
      expect(page.at_css("#open_list_pager a[rel=prev]")).to be_nil

      # A package no longer listed, or a cursor that is not one, reads the first page.
      [ "gone:amd64", "nocolon", ":amd64", "x" * 200 ].each do |cursor|
        get "/hosts/#{host.id}/vulnerabilities", params: { after: cursor }
        expect(rows.map { |row| row.split.first }).to eq(%w[ssl:amd64 kernel:amd64]), cursor
      end
      get "/hosts/#{host.id}/vulnerabilities", params: { before: "gone:amd64" }
      expect(rows.map { |row| row.split.first }).to eq(%w[ssl:amd64 kernel:amd64])

      report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ])
      match(host)
      get "/hosts/#{host.id}/vulnerabilities", params: { state: "all", after: "kernel:amd64" } # the open section's cursor leaves the resolved one
      expect(page.css("#resolved_list > tbody > tr.pkg-group").map { |row| words(row).split.first }).to eq(%w[ssl:amd64 kernel:amd64])
      href = page.at_css("#resolved_list_pager a[rel=next]")["href"]
      expect(Rack::Utils.parse_query(URI(href).query)).to eq("state" => "all", "resolved_after" => "kernel:amd64")
      get href
      expect(page.css("#resolved_list > tbody > tr.pkg-group").map { |row| words(row).split.first }).to eq(%w[curl:amd64 zlib:amd64])
    end
  end

  it "says evaluated and nothing found only when the host was evaluated" do
    host = debian_host(packages: [ [ "bash", "5.2.37-1", "bash" ] ])
    import_advisories(advisory("DSA-9100-1", "acme"), full: true)
    match(host)
    get "/hosts/#{host.id}/vulnerabilities"
    expect(words(page.at_css("#no_open_findings"))).to eq("No open vulnerability findings. Evaluated 2026-11-06 09:00 UTC: 1 package matched against 1 Debian:13 advisory. 0 resolved findings.")
    expect(page.at_css("#not_evaluated")).to be_nil
    expect(page.css("nav.tabs a").map { |a| words(a) }.grep(/\AVulnerabilities/).sole).to eq("Vulnerabilities 0 open")
    expect(words(page.at_css("#glance_vulns"))).to eq("Open vulnerabilities None open Evaluated less than 5 seconds ago")
  end

  describe "a host that cannot be evaluated says so and why, never an empty list" do
    def notice(host)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(page.at_css("#open_list")).to be_nil
      expect(page.at_css("#no_open_findings")).to be_nil
      words(page.at_css("#not_evaluated"))
    end

    before { import_advisories(advisory("DSA-9100-1", "acme"), full: true) }

    it "for each of the matcher's reasons, with what to do next" do
      bare = enrolled_host.first
      match(bare)
      expect(notice(bare)).to eq("Not evaluated: this host's vulnerabilities are unknown, not zero. #{HostContext::REASONS['no_inventory']} " \
                                 "Reason no_inventory . It is evaluated as soon as the agent sends its first inventory and package reports.")
      alpine = debian_host(os: { "id" => "alpine", "version_id" => "3.20", "pretty_name" => "Alpine" })
      match(alpine)
      expect(notice(alpine)).to include("alpine 3.20 is not in the fleet profile (DEC-01)", "Reason unmapped_distribution . Adding a distribution needs a new decision")
      unreported = debian_host(packages: nil)
      match(unreported)
      expect(notice(unreported)).to include("The host has not reported its packages.", "Reason no_package_report . Request a package report or wait for the next scheduled one.")
      expect(page.at_css("#not_evaluated a")["href"]).to eq("/hosts/#{unreported.id}/packages#request")
      apk = debian_host(packages: nil)
      report_packages(apk, [], manager: "unsupported", unsupported_reason: "apk is not supported by this agent version")
      match(apk)
      expect(notice(apk)).to include("The host's package manager is not supported: apk is not supported by this agent version", "Reason unsupported_package_manager .")
      expect(page.css("nav.tabs a").map { |a| words(a) }.grep(/\AVulnerabilities/).sole).to eq("Vulnerabilities Not evaluated")
      expect(words(page.at_css("#glance_vulns"))).to eq("Open vulnerabilities Not evaluated The host's package manager is not supported: apk is not supported by this agent version")
    end

    it "for a host whose package database could not be read, keeping its findings (P2-S08)" do
      host = debian_host(packages: [ [ "acme", "1.0-1", "acme" ] ])
      match(host)
      report_packages(host, [], manager: "unreadable", unsupported_reason: "dpkg-query exited with status 2")
      match(host)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#not_evaluated"))).to include("The host's package database could not be read, so its packages are not matched: dpkg-query exited with status 2",
                                                              "Reason unreadable_packages . Its findings are matched again after the next package report that can be read")
      expect(groups("open_list").map(&:first)).to eq([ "acme:amd64 installed 1.0-1 1 advisory High 1 high Fix available 1 open 2026-11-06 09:00 UTC" ])
      expect(page.css("nav.tabs a").map { |a| words(a) }.grep(/\AVulnerabilities/).sole).to eq("Vulnerabilities 1 open")
    end

    it "before matching has run, and when no advisory data has been imported" do
      host = debian_host(packages: [ [ "acme", "1.0-1", "acme" ] ])
      expect(notice(host)).to eq("Not evaluated yet: this host's vulnerabilities are unknown, not zero. Its packages have not been matched against advisories yet. " \
                                 "Matching runs after each new package report and each advisory import.")
      unreported = debian_host(packages: nil)
      expect(notice(unreported)).to include("The host has not reported its packages.", "Reason no_package_report")
      AdvisoryImport.delete_all
      match(host)
      expect(notice(host)).to include("No advisory data has been imported for Debian:13.", "Reason no_advisory_data . Check the failed jobs : the first refresh may have failed or not run yet.")
      expect(page.at_css("#advisory_freshness").text.squish).to start_with("Vulnerability data has never been refreshed.")
    end

    it "keeps findings from an earlier evaluation, saying they may be out of date" do
      host = debian_host(packages: [ [ "acme", "1.0-1", "acme" ] ])
      match(host)
      report_packages(host, [], manager: "unsupported", unsupported_reason: "apk is not supported by this agent version")
      match(host)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#not_evaluated"))).to start_with("Not evaluated now. The open findings below are from an earlier evaluation.")
      expect(page.at_css("#not_evaluated").text).to include("They may be out of date")
      expect(groups("open_list").map(&:first)).to eq([ "acme:amd64 installed 1.0-1 1 advisory High 1 high Fix available 1 open 2026-11-06 09:00 UTC" ])
      expect(page.css("nav.tabs a").map { |a| words(a) }.grep(/\AVulnerabilities/).sole).to eq("Vulnerabilities 1 open")
    end
  end

  it "links an advisory only to an http or https address, and escapes advisory and package text (NFR-1)" do
    host = debian_host(packages: [ [ "acme", "1.0-1", "acme" ] ])
    import_advisories(advisory("DSA-9100-1", "acme"), full: true)
    match(host)
    Advisory.update_all(summary: HOSTILE, reference_url: "javascript:alert(1)")
    get "/hosts/#{host.id}/vulnerabilities"
    expect(page.css("#open_list a").map { |a| a["href"] }).to eq([ "/hosts/#{host.id}/vulnerabilities/package?package=acme" ])
    expect(page.at_css("#open_list tr.nested").text).to include("No link recorded", HOSTILE)
    expect(page.css("img[onerror]")).to be_empty
    %w[ftp://security.example.lan/x https:///no-host http://security.example.lan/a\ b].each do |url|
      Advisory.update_all(reference_url: url)
      get "/hosts/#{host.id}/vulnerabilities/package?package=acme"
      expect(page.css("#package_findings a")).to be_empty, url
    end
    Advisory.update_all(reference_url: "http://[bad")
    get "/hosts/#{host.id}/vulnerabilities/package?package=acme"
    expect(page.at_css("#package_findings").text).to include("No link recorded")
  end

  it "escapes a reason that names the host's own distribution (NFR-1)" do
    host = debian_host(os: { "id" => HOSTILE, "version_id" => "1", "pretty_name" => HOSTILE })
    match(host)
    get "/hosts/#{host.id}/vulnerabilities"
    expect(page.at_css("#not_evaluated").text).to include(HOSTILE.downcase, "is not in the fleet profile")
    expect(page.css("script:not([nonce])")).to be_empty
    expect(page.css("img[onerror]")).to be_empty
  end

  describe "review of #120" do
    def package_page(host, name) = get("/hosts/#{host.id}/vulnerabilities/package?package=#{name}")

    it "does not show a green No findings before matching ran, with no advisory data, or when not evaluated (comment 4502879079)" do
      host = debian_host(name: "Media server", packages: [ [ "bash", "5.2.37-1", "bash" ] ])
      import_advisories(advisory("DSA-9100-1", "acme"), full: true)
      package_page(host, "bash") # before matching has run
      expect(page.at_css("#package_summary .none-open")).to be_nil
      expect(words(page.at_css("#findings_unknown"))).to start_with("Not known.")
      expect(words(page.at_css("#not_evaluated"))).to start_with("Not evaluated yet:")
      AdvisoryImport.delete_all
      match(host) # no advisory data has been imported
      package_page(host, "bash")
      expect(page.at_css("#package_summary .none-open")).to be_nil
      expect(page.at_css("#not_evaluated").text).to include("No advisory data has been imported for Debian:13.", "Reason no_advisory_data")
      import_advisories(advisory("DSA-9100-1", "acme"), full: true)
      match(host)
      package_page(host, "bash")
      expect(page.at_css("#not_evaluated")).to be_nil
      expect(words(page.at_css("#package_summary .none-open"))).to eq("No findings.")
    end

    it "says a package whose advisories could not be compared was not fully checked, and so for one the cut-short list may hold" do
      host = debian_host(name: "Media server", packages: [ [ "weird", "1:", "weird" ], [ "bash", "5.2.37-1", "bash" ] ])
      import_advisories(advisory("DSA-9100-1", "weird"), full: true)
      match(host)
      package_page(host, "weird")
      expect(page.at_css("#package_summary .none-open")).to be_nil
      expect(words(page.at_css("#findings_unchecked"))).to eq("No findings recorded, but not everything was checked. 1 advisory could not be compared for this package, listed below.")
      expect(page.css("#unchecked_for_package li").map { |li| words(li) }.first).to start_with("DSA-9100-1 at 1:")
      package_page(host, "bash")
      expect(words(page.at_css("#package_summary .none-open"))).to eq("No findings.")
      HostVulnerabilityEvaluation.update_all(not_evaluated_count: 150) # the matcher keeps the first 100
      package_page(host, "bash")
      expect(page.at_css("#package_summary .none-open")).to be_nil
      expect(words(page.at_css("#findings_unchecked"))).to include("keeps only the first 1")
    end

    it "describes the fix of the recorded range, without promising that every later version is safe (comment 4502879109)" do
      host = debian_host(name: "Media server", packages: [ [ "acme", "1.1-1", "acme" ] ])
      ranges = [ { "type" => "ECOSYSTEM", "events" => [ { "introduced" => "1.0-1" }, { "fixed" => "1.2-1" } ] },
                 { "type" => "ECOSYSTEM", "events" => [ { "introduced" => "1.4-1" } ] } ]
      import_advisories(advisory("DSA-9100-1", "acme").tap { |r| r["affected"][0]["ranges"] = ranges }, full: true)
      match(host)
      package_page(host, "acme")
      text = page.at_css("#package_summary").text.squish
      expect(text).to include("For DSA-9100-1, the affected range the installed version is in is fixed in 1.2-1. Check the advisory for any other affected range")
      expect(text).not_to include("or later resolves it")
    end

    it "does not say the package was updated when an advisory's ranges changed and the installed version is unchanged (comment 4502879140)" do
      host = debian_host(name: "Media server", packages: [ [ "acme", "1.0-1", "acme" ] ])
      import_advisories(advisory("DSA-9100-1", "acme"), full: true)
      match(host)
      travel_to(start + 1.hour) { import_advisories(advisory("DSA-9100-1", "acme", modified: "2026-11-01T00:00:00Z", introduced: "1.5-1", fixed: "2.0-1")) }
      match(host, at: start + 1.hour)
      package_page(host, "acme")
      row = package_rows.first
      expect(row[5]).to eq("Resolved Fixed: the installed version is outside the affected ranges")
      expect(row[6]).to include("resolved: fixed: the installed version is outside the affected ranges")
      expect(page.text).not_to include("package updated")
    end

    it "shows the advisory data freshness on the package page (comment 4502879171)" do
      host = debian_host(name: "Media server", packages: [ [ "acme", "1.0-1", "acme" ] ])
      import_advisories(advisory("DSA-9100-1", "acme"), full: true)
      match(host)
      package_page(host, "acme")
      expect(page.at_css("#advisory_freshness").text.squish).to start_with("Advisory data last updated:")
      AdvisoryImport.delete_all
      package_page(host, "acme")
      expect(page.at_css("#advisory_freshness[role=alert]").text.squish).to start_with("Vulnerability data has never been refreshed.")
    end

    it "says whether a package is installed is not known when the package manager is unsupported, not that it is not installed (comment 4502879203)" do
      host = debian_host(name: "Media server", packages: [ [ "acme", "1.0-1", "acme" ] ])
      import_advisories(advisory("DSA-9100-1", "acme"), full: true)
      match(host)
      report_packages(host, [], manager: "unsupported", unsupported_reason: "apk is not supported by this agent version")
      match(host)
      package_page(host, "acme")
      expect(response).to have_http_status(:ok)
      expect(words(page.at_css("#installation_unknown"))).to start_with("Whether it is installed is not known: the host's package manager is not supported")
      expect(page.at_css("#installed_package").text).not_to include("Not installed now")
      expect(page.at_css("#not_evaluated")).to be_present
    end

    it "says an unreadable package database leaves the installed package as the last readable report had it" do
      host = debian_host(name: "Media server", packages: [ [ "acme", "1.0-1", "acme" ] ])
      import_advisories(advisory("DSA-9100-1", "acme"), full: true)
      match(host)
      report_packages(host, [], manager: "unreadable", unsupported_reason: "dpkg-query exited with status 2")
      package_page(host, "acme")
      expect(page.at_css("#installation_last_readable").text).to include("From the last package report that could be read")
      expect(page.at_css("#installed_package").text).to include("Version 1.0-1".squish.sub("Version ", ""))
    end
  end
end
