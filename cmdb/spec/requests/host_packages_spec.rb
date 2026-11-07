require "rails_helper"
require "benchmark"

# The Packages tab and the package snapshot comparison (P2-D03, FR-2.3, FR-2.5; approved mockups host-packages.html,
# host-packages-diff.html, states-packages-vulns.html).
RSpec.describe "Host packages", :signed_in, type: :request do
  let(:start) { Time.utc(2026, 11, 6, 9, 0, 0) }
  let!(:host) { enrolled_host(name: "Media server").first }

  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later) # matching is run by hand
    travel_to(start)
    record_heartbeat(host)
    record_inventory(host) # Debian 13
  end

  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  def rows = page.css("#package_list tbody tr").map { |row| row.css("td").map { |td| words(td) } }

  def names = page.css("#package_list tbody tr td:first-child").map(&:text)

  def report(packages, at:, **options) = travel_to(at) { report_packages(host, packages, **options) }

  def snapshots = PackageSnapshot.where(host:).order(:received_at).to_a

  it "says there is no package report yet, with the button to ask for one" do
    get "/hosts/#{host.id}/packages"
    expect(response).to have_http_status(:ok)
    expect(words(page.at_css("#no_packages"))).to start_with("No package report yet.")
    expect(page.at_css("#request button").text).to eq("Request fresh package report")
    expect(page.at_css("#package_list")).to be_nil
    expect(page.css("nav.tabs a").map { |a| a.text.squish }).to eq(%w[Overview Configuration Packages])
  end

  context "with a package set" do
    let(:packages) do
      [ [ "openssl", "3.5.0-1", "openssl" ], [ "libssl3", "3.5.0-1", "openssl" ], [ "bash", "5.2.37-1", "bash" ], [ "zlib1g", "1:1.3.dfsg-3", "zlib" ],
        [ "acme-docs", "4.0-1", "acme-docs", "all" ], [ "bsdutils", "1:2.41-5", "util-linux" ], { "name" => "nosource", "version" => "1.0", "architecture" => "amd64" } ]
    end

    before { report(packages, at: start + 1.minute) }

    it "lists the package manager's set with version, architecture, source package, and manager, sorted by name" do
      get "/hosts/#{host.id}/packages"
      expect(page.at_css("#current_section > p.muted").text.squish).to start_with("7 packages from dpkg.")
      expect(names).to eq(%w[acme-docs bash bsdutils libssl3 nosource openssl zlib1g])
      expect(rows.first).to eq([ "acme-docs", "4.0-1", "all", "acme-docs", "dpkg", "—" ])
      expect(rows[4]).to eq([ "nosource", "1.0", "amd64", "—", "dpkg", "—" ])
      expect(page.at_css("th[aria-sort=ascending]").text).to eq("Package")
      expect(words(page.at_css("#package_pager"))).to eq("Packages 1–7 of 7 Previous · Page 1 of 1 · Next")
      expect(page.css("nav.tabs a").map { |a| words(a) }).to eq([ "Overview", "Configuration", "Packages 7" ])
      expect(words(page.at_css("#glance_packages"))).to eq("Packages 7 dpkg, set last changed 1 minute ago")
      expect(page.at_css("#glance_packages")["href"]).to eq("/hosts/#{host.id}/packages")
    end

    it "searches name and source package, filters by architecture, and sorts, keeping it all in the URL" do
      get "/hosts/#{host.id}/packages", params: { q: "SSL" }
      expect(names).to eq(%w[libssl3 openssl])
      expect(words(page.at_css("#package_pager"))).to start_with("Packages 1–2 of 2 matching")
      get "/hosts/#{host.id}/packages", params: { q: "util-linux" }
      expect(names).to eq(%w[bsdutils])
      get "/hosts/#{host.id}/packages", params: { arch: "all" }
      expect(names).to eq(%w[acme-docs])
      get "/hosts/#{host.id}/packages", params: { arch: "sparc", sort: "source", dir: "desc", q: "s" }
      expect(names).to eq(%w[bsdutils libssl3 openssl bash acme-docs nosource])
      expect(page.at_css("th[aria-sort=descending]").text).to eq("Source package")
      version_link = page.css("th a").find { |a| a.text == "Version" }["href"]
      expect(Rack::Utils.parse_query(URI(version_link).query)).to eq("q" => "s", "sort" => "version")
      expect(page.at_css("#package_filters input[name=sort]")["value"]).to eq("source")
      get version_link
      expect(names).to eq(%w[nosource bsdutils libssl3 openssl acme-docs bash]) # as text: "1.0" < "1:2.41-5" < "3.5.0-1"
      get "/hosts/#{host.id}/packages", params: { q: "zzz", arch: "amd64" }
      expect(words(page.at_css("#no_matches"))).to eq(%(No packages match "zzz" on architecture "amd64". Clear the search and filters))
    end

    it "shows open findings per package and filters to packages that have them" do
      import_advisories(osv_record(id: "DSA-9100-1", package: "openssl", fixed: "3.5.1-1"), osv_record(id: "DSA-9101-1", package: "openssl", fixed: "3.5.2-1"), full: true)
      VulnerabilityMatcher.match!([ host.id ])
      VulnerabilityFinding.where(package: "libssl3", advisory: Advisory.find_by!(advisory_id: "DSA-9101-1")).update_all(state: "reopened", reopened_at: Time.current)
      get "/hosts/#{host.id}/packages", params: { findings: "open" }
      expect(rows.map { |row| [ row.first, row.last ] }).to eq([ [ "libssl3", "2 open (reopened)" ], [ "openssl", "2 open" ] ])
      expect(page.at_css("#package_filters select[name=findings] option[selected]")["value"]).to eq("open")
      get "/hosts/#{host.id}/packages", params: { findings: "open", q: "bash" }
      expect(words(page.at_css("#no_matches"))).to start_with(%(No packages match "bash" with open findings.))
    end

    it "lists snapshots with what changed and comparison links" do
      report(packages.drop(1) + [ [ "curl", "8.14.1-2", "curl" ] ], at: start + 1.hour)
      get "/hosts/#{host.id}/packages"
      expect(page.css("#snapshot_list tbody tr").map { |row| row.css("td").map { |td| words(td) } }).to eq([
        [ "2026-11-06 10:00 UTC Latest", "1 installed, 1 removed", "With the one before" ],
        [ "2026-11-06 09:01 UTC", "Oldest package snapshot kept, 7 packages", "No earlier snapshot kept" ]
      ])
      first, latest = snapshots
      expect(page.at_css("#snapshot_list a")["href"]).to eq("/hosts/#{host.id}/packages/compare?from=#{first.id}&to=#{latest.id}")
    end

    it "asks for a package report only, and comes back to the Packages tab" do
      get "/hosts/#{host.id}/packages"
      expect(words(page.at_css("#request"))).to start_with("Package report received 1 minute ago.")
      expect(page.css("#request input[type=hidden]").to_h { |input| [ input["name"], input["value"] ] }).to include("report_types[]" => "packages", "return_to" => "packages")
      post "/hosts/#{host.id}/request_reports", params: { report_types: %w[packages], return_to: "packages" }
      expect(response).to redirect_to("/hosts/#{host.id}/packages#request")
      follow_redirect!
      expect(page.at_css("#request button")["disabled"]).to eq("disabled")
    end
  end

  it "pages through a large set 50 at a time, and clamps a page past the end" do
    report(Array.new(120) { |i| [ format("pkg-%03d", i), "1.0-#{i}", "src-#{i % 7}" ] }, at: start)
    get "/hosts/#{host.id}/packages", params: { page: 2, q: "pkg" }
    expect(names.first).to eq("pkg-050")
    expect(names.size).to eq(50)
    expect(words(page.at_css("#package_pager"))).to eq("Packages 51–100 of 120 matching Previous · Page 2 of 3 · Next")
    expect(Rack::Utils.parse_query(URI(page.at_css("#package_pager a[rel=prev]")["href"]).query)).to eq("q" => "pkg")
    expect(Rack::Utils.parse_query(URI(page.at_css("#package_pager a[rel=next]")["href"]).query)).to eq("q" => "pkg", "page" => "3")
    get "/hosts/#{host.id}/packages", params: { page: 9 }
    expect(names.first).to eq("pkg-100")
    expect(words(page.at_css("#package_pager"))).to eq("Packages 101–120 of 120 Previous · Page 3 of 3 · Next")
    get "/hosts/#{host.id}/packages", params: { page: 3 }
    expect(URI(page.at_css("#package_pager a[rel=prev]")["href"]).query).to eq("page=2")
  end

  it "loads a 3,000-package host quickly: one page of rows in a fixed number of queries (P2-D03)" do
    big = Array.new(3_000) { |i| [ format("package-%04d", i), "2.#{i}-1", "source-#{i % 400}" ] }
    report(big, at: start)
    report(big.drop(5) + [ [ "newcomer", "1.0-1", "newcomer" ] ], at: start + 1.hour)
    get "/hosts/#{host.id}/packages" # warm up: templates, the manifest, and the query cache plan
    timings = Array.new(3) do
      queries = nil
      elapsed = Benchmark.realtime { queries = count_queries { get "/hosts/#{host.id}/packages", params: { q: "package-1", sort: "version", dir: "desc", page: 2 } } }
      [ elapsed, queries ]
    end
    expect(response).to have_http_status(:ok)
    expect(names.size).to eq(50)
    expect(timings.map(&:last).uniq.size).to eq(1)
    expect(timings.map(&:last).first).to be <= 40
    expect(timings.map(&:first).min).to be < 1.5 # measured about 0.15 s on a laptop; generous for a shared CI runner
    puts format("\n  3,000-package host, Packages tab: %.0f ms (best of 3), %d queries", timings.map(&:first).min * 1000, timings.first.last) if ENV["SHOW_TIMINGS"]
  end

  describe "comparing snapshots" do
    before do
      report([ [ "acme-daemon", "2.4.0-1", "acme-daemon" ], [ "acme-ftpd", "0.9-3", "acme-ftpd" ], [ "acme-tools", "1:7.8p1-5", "acme-suite" ],
               [ "acme-prototype", "2.0_rc1", "acme-prototype" ], [ "libacmeutil1", "1.1-2", "acme-suite" ], [ "bash", "5.2.37-1", "bash" ] ], at: start)
      report([ [ "acme-daemon", "2.4.1-2", "acme-daemon" ], [ "acme-tools", "1:7.8p1-4", "acme-suite" ], [ "acme-prototype", "x:2.0", "acme-prototype" ],
               [ "libacmeutil1", "1.1-2", "acme-utils" ], [ "bash", "5.2.37-1", "bash" ], [ "acme-docs", "4.0-1", "acme-docs", "all" ] ], at: start + 1.hour)
    end

    it "shows an install, a removal, an upgrade, a downgrade, a version it cannot compare, and a source change, by default the latest against the one before" do
      get "/hosts/#{host.id}/packages/compare"
      expect(response).to have_http_status(:ok)
      expect(words(page.at_css("#diff_summary"))).to eq("+ Installed 1 − Removed 1 ↑ Upgraded 1 ↓ Downgraded 1 ? Cannot compare 1 ∼ Source changed 1")
      expect(page.css("#package_changes tbody tr").map { |row| row.css("td").map { |td| words(td) } }).to eq([
        [ "acme-docs:all", "+ Installed", "Not installed", "4.0-1", "acme-docs" ],
        [ "acme-ftpd:amd64", "− Removed", "0.9-3", "Not installed", "acme-ftpd" ],
        [ "acme-daemon:amd64", "↑ Upgraded", "2.4.0-1", "2.4.1-2", "acme-daemon" ],
        [ "acme-tools:amd64", "↓ Downgraded", "1:7.8p1-5", "1:7.8p1-4", "acme-suite" ],
        [ "acme-prototype:amd64", "? Cannot compare", "2.0_rc1", "x:2.0", "acme-prototype" ],
        [ "libacmeutil1:amd64", "∼ Source changed", "1.1-2 from acme-suite", "1.1-2 from acme-utils", "acme-utils" ]
      ])
      first, latest = snapshots
      expect(page.at_css("#snapshot_picker select[name=from] option[selected]")["value"]).to eq(first.id.to_s)
      expect(page.css("#snapshot_picker select[name=to] option").map(&:text)).to eq([ "2026-11-06 10:00 UTC (latest, 6 packages)", "2026-11-06 09:00 UTC (oldest kept, 6 packages)" ])
      expect(page.at_css("#snapshot_picker select[name=to] option[selected]")["value"]).to eq(latest.id.to_s)
      expect(page.at_css("title").text).to eq("Media server: compare package snapshots · Fleet CMDB")
    end

    it "filters by kind, compares newer to older with Swap, and refuses another host's snapshot" do
      first, latest = snapshots
      get "/hosts/#{host.id}/packages/compare", params: { from: first.id, to: latest.id, kind: "upgraded" }
      expect(page.css("#package_changes tbody tr td:first-child").map(&:text)).to eq([ "acme-daemon:amd64" ])
      expect(page.at_css("#kind_filters a[aria-current]").text.squish).to eq("Upgraded 1")
      get "/hosts/#{host.id}/packages/compare", params: { from: first.id, to: latest.id, kind: "bogus" }
      expect(page.at_css("#kind_filters a[aria-current]").text.squish).to eq("All changes 6")
      get page.at_css("#snapshot_picker a.btn")["href"]
      expect(page.at_css("#reversed_note")).to be_present
      expect(page.css("#package_changes tbody tr").map { |row| row.css("td")[0..1].map { |td| words(td) } })
        .to include([ "acme-ftpd:amd64", "+ Installed" ], [ "acme-docs:all", "− Removed" ], [ "acme-daemon:amd64", "↓ Downgraded" ], [ "acme-tools:amd64", "↑ Upgraded" ])
      get "/hosts/#{host.id}/packages/compare", params: { from: first.id, to: latest.id, kind: "removed" }
      expect(page.css("#package_changes tbody tr").size).to eq(1)
      other = enrolled_host.first
      report_packages(other, [ [ "bash", "5.2.37-1", "bash" ] ])
      get "/hosts/#{host.id}/packages/compare", params: { from: PackageSnapshot.find_by!(host: other).id, to: latest.id }
      expect(response).to have_http_status(:not_found)
    end

    it "says the same packages, and no changes of a kind" do
      first, = snapshots
      get "/hosts/#{host.id}/packages/compare", params: { from: first.id, to: first.id }
      expect(page.at_css("#no_changes").text).to eq("The two snapshots list the same packages.")
      get "/hosts/#{host.id}/packages/compare", params: { from: first.id, to: snapshots.last.id, kind: "invalid" }
      expect(page.css("#package_changes tbody tr").size).to eq(1)
      report([ [ "bash", "5.2.37-1", "bash" ] ], at: start + 2.hours)
      get "/hosts/#{host.id}/packages/compare", params: { from: snapshots[1].id, to: snapshots.last.id, kind: "upgraded" }
      expect(page.at_css("#no_changes").text).to eq("No changes of this kind.")
    end
  end

  describe "an unsupported package manager" do
    before do
      report([ [ "bash", "5.2.37-1", "bash" ] ], at: start)
      report([], at: start + 1.hour, manager: "unsupported", unsupported_reason: "apk is not supported by this agent version")
    end

    it "says the packages are unknown, never an empty list, in the tab, the tile, and the snapshot list" do
      get "/hosts/#{host.id}/packages"
      expect(words(page.at_css("#unsupported_manager"))).to eq("This host's package manager is not supported, so its packages are unknown. " \
                                                               "The agent reported: apk is not supported by this agent version . Supported package managers: dpkg. This is not an empty package list.")
      expect(page.at_css("#package_list")).to be_nil
      expect(page.css("nav.tabs a").map { |a| words(a) }.last).to eq("Packages Unsupported")
      expect(words(page.at_css("#glance_packages"))).to eq("Packages Not known Unsupported package manager")
      expect(page.css("#snapshot_list tbody tr td:nth-child(2)").map { |td| words(td) }).to eq([ "No diff: one side is from an unsupported package manager", "Oldest package snapshot kept, 1 package" ])
    end

    it "has no diff for a pair with an unsupported side" do
      get "/hosts/#{host.id}/packages/compare"
      expect(words(page.at_css("#no_diff"))).to start_with("No diff is available for this pair.")
      expect(page.at_css("#package_changes")).to be_nil
      expect(page.css("#snapshot_picker select[name=to] option").first.text).to eq("2026-11-06 10:00 UTC (latest, unsupported manager)")
    end

    it "escapes the agent's reason (NFR-1)" do
      report([], at: start + 2.hours, manager: "unsupported", unsupported_reason: HOSTILE)
      get "/hosts/#{host.id}/packages"
      expect(page.css("script:not([nonce])")).to be_empty
      expect(page.css("img[onerror]")).to be_empty
      expect(page.at_css("#unsupported_manager .mono").text).to eq(HOSTILE)
    end
  end

  describe "review of #119" do
    it "calls a version dpkg treats as equal an equivalent version, and keeps Source changed for a changed source (comment 4502877664)" do
      report([ [ "tzdata", "1.0", "tzdata" ], [ "acme", "2.0", "acme-old" ] ], at: start)
      report([ [ "tzdata", "0:1.0", "tzdata" ], [ "acme", "2.0", "acme-new" ] ], at: start + 1.hour)
      get "/hosts/#{host.id}/packages/compare"
      expect(page.css("#diff_summary li").map { |li| words(li) }).to include("∼ Source changed 1", "≈ Equivalent version 1")
      rows = page.css("#package_changes tbody tr").map { |tr| tr.css("td").map { |td| words(td) } }
      expect(rows).to eq([ [ "acme:amd64", "∼ Source changed", "2.0 from acme-old", "2.0 from acme-new", "acme-new" ],
                           [ "tzdata:amd64", "≈ Equivalent version", "1.0 from tzdata", "0:1.0 from tzdata", "tzdata" ] ])
      get "/hosts/#{host.id}/packages"
      expect(words(page.at_css("#snapshot_list tbody tr td:nth-child(2)"))).to eq("1 source changed, 1 equivalent version")
      get "/hosts/#{host.id}/packages/compare", params: { from: snapshots.first.id, to: snapshots.last.id, kind: "equivalent" }
      expect(page.css("#package_changes tbody tr td:first-child").map(&:text)).to eq([ "tzdata:amd64" ])
    end

    it "shows no Equivalent version counter when nothing is respelled (the page as drawn in the mockup)" do
      report([ [ "tzdata", "1.0", "tzdata" ] ], at: start)
      report([ [ "tzdata", "1.1", "tzdata" ] ], at: start + 1.hour)
      get "/hosts/#{host.id}/packages/compare"
      expect(page.css("#diff_summary li").map { |li| words(li) }).to eq([ "+ Installed 0", "− Removed 0", "↑ Upgraded 1", "↓ Downgraded 0", "? Cannot compare 0", "∼ Source changed 0" ])
    end

    it "explains Upgraded and Downgraded by the From and To direction after Swap (comment 4502877692)" do
      report([ [ "tzdata", "2.0", "tzdata" ] ], at: start)
      report([ [ "tzdata", "1.0", "tzdata" ] ], at: start + 1.hour)
      first, last = snapshots.map(&:id)
      get "/hosts/#{host.id}/packages/compare", params: { from: last, to: first }
      expect(page.at_css("#package_changes tbody tr").css("td").map { |td| words(td) }.first(4)).to eq([ "tzdata:amd64", "↑ Upgraded", "1.0", "2.0" ])
      expect(words(page.at_css("#reversed_note"))).to eq("Compared newer to older. Changes read from the From snapshot to the To snapshot, " \
                                                         "so an upgrade here is a package whose version is higher in the earlier snapshot (To), and a downgrade one whose version is lower there.")
    end

    it "calls the oldest snapshot still kept that, not the host's first report, once older ones are pruned (comment 4502877714)" do
      report([ [ "bash", "5.2.37-1", "bash" ] ], at: start)
      report([ [ "bash", "5.2.37-1", "bash" ], [ "vim", "2:9.1-1", "vim" ] ], at: start + 1.hour)
      snapshots.first.destroy # what Retention does to snapshots past the window
      get "/hosts/#{host.id}/packages"
      expect(page.css("#snapshot_list tbody tr").map { |tr| tr.css("td").map { |td| words(td) } }).to eq([ [ "2026-11-06 10:00 UTC Latest", "Oldest package snapshot kept, 2 packages", "No earlier snapshot kept" ] ])
      expect(page.text).not_to include("First package report", "Nothing before it")
    end
  end

  describe "skipped packages (P2-S08)" do
    let(:skipped) { [ { "name" => "vim", "reason" => "half-configured" }, { "name" => "never-seen", "reason" => "unpacked" } ] }

    before do
      report([ [ "bash", "5.2.37-1", "bash" ], [ "vim", "2:9.1-1", "vim" ], [ "curl", "8.14-1", "curl" ], [ "tzdata", "2025a-1", "tzdata", "all" ] ], at: start)
      report([ [ "bash", "5.2.37-1", "bash" ], [ "tzdata", "2025b-1", "tzdata", "all" ] ], at: start + 1.hour, skipped:)
    end

    it "shows a package that is absent and named as skipped as Skipped / incomplete with its reason, and not as removed" do
      get "/hosts/#{host.id}/packages/compare"
      expect(page.css("#diff_summary li").map { |li| words(li) }).to eq([ "+ Installed 0", "− Removed 1", "↑ Upgraded 1", "↓ Downgraded 0", "? Cannot compare 0", "∼ Source changed 0", "◌ Skipped / incomplete 1" ])
      rows = page.css("#package_changes tbody tr").map { |tr| [ tr["class"], tr.css("td").map { |td| words(td) } ] }
      expect(rows).to include([ "change skipped", [ "vim:amd64", "◌ Skipped / incomplete", "2:9.1-1", "Not listed as installed half-configured", "vim" ] ])
      expect(rows).to include([ "change removed", [ "curl:amd64", "− Removed", "8.14-1", "Not installed", "curl" ] ])
      expect(rows.map { |_, cells| cells.first }).not_to include("never-seen:amd64")
      expect(page.at_css("tr.change.skipped del")).to be_nil # not struck through like a removal
    end

    it "filters the comparison to the skipped packages" do
      from, to = snapshots.map(&:id)
      get "/hosts/#{host.id}/packages/compare", params: { from:, to:, kind: "skipped" }
      expect(page.css("#package_changes tbody tr").map { |tr| tr.css("td").first.text }).to eq([ "vim:amd64" ])
      expect(page.at_css("#kind_filters a[aria-current=true]").text.squish).to eq("Skipped / incomplete 1")
    end

    it "counts it in the snapshot list's summary, not as removed" do
      get "/hosts/#{host.id}/packages"
      expect(page.css("#snapshot_list tbody tr td:nth-child(2)").map { |td| words(td) }.first).to eq("1 removed, 1 skipped or incomplete, 1 upgraded")
    end

    it "shows no skipped row for a package that is skipped but was never installed, or is still listed" do
      report([ [ "bash", "5.2.37-1", "bash" ], [ "tzdata", "2025b-1", "tzdata", "all" ] ], at: start + 2.hours, skipped: [ { "name" => "bash", "reason" => "unpacked" } ])
      get "/hosts/#{host.id}/packages/compare"
      expect(page.css("#package_changes")).to be_empty
      expect(page.at_css("#no_changes").text).to eq("The two snapshots list the same packages.")
    end

    it "escapes the agent's reason (NFR-1)" do
      report([ [ "bash", "5.2.37-1", "bash" ], [ "tzdata", "2025b-1", "tzdata", "all" ] ], at: start + 2.hours, skipped: [ { "name" => "vim", "reason" => HOSTILE } ])
      get "/hosts/#{host.id}/packages/compare", params: { from: snapshots.first.id, to: snapshots.last.id }
      expect(page.css("script:not([nonce])")).to be_empty
      expect(page.css("img[onerror]")).to be_empty
      expect(page.at_css("tr.change.skipped td:nth-child(4) .mono").text).to eq(HOSTILE)
    end
  end

  describe "an unreadable package database (P2-S08)" do
    before do
      report([ [ "bash", "5.2.37-1", "bash" ], [ "vim", "2:9.1-1", "vim" ] ], at: start)
      report([], at: start + 1.hour, manager: "unreadable", unsupported_reason: "dpkg-query exited with status 2")
    end

    it "says the list may be out of date, with the reason and the last readable report, and still lists the kept packages" do
      get "/hosts/#{host.id}/packages"
      expect(words(page.at_css("#unreadable_packages"))).to eq("The agent could not read this host's package database, so the list below may be out of date. " \
                                                               "The agent reported: dpkg-query exited with status 2 . The list is from the report of 2026-11-06 09:00 UTC, the last one that could be read. This is not an empty package list.")
      expect(names).to eq(%w[bash vim])
      expect(page.css("nav.tabs a").map { |a| words(a) }).to include("Packages 2")
      expect(words(page.at_css("#glance_packages"))).to eq("Packages 2 Last report could not be read, list is from the last one that could")
      expect(page.css("#snapshot_list tbody tr td:nth-child(2)").map { |td| words(td) }).to eq([ "No diff: one side is a report whose package database could not be read", "Oldest package snapshot kept, 2 packages" ])
    end

    it "compares the snapshot after it with the one before it, and has no diff for the unreadable one" do
      report([ [ "bash", "5.2.37-1", "bash" ] ], at: start + 2.hours)
      get "/hosts/#{host.id}/packages"
      expect(page.css("#snapshot_list tbody tr td:nth-child(2)").map { |td| words(td) }.first).to eq("1 removed")
      get "/hosts/#{host.id}/packages/compare", params: { from: snapshots.first.id, to: snapshots[1].id }
      expect(words(page.at_css("#no_diff"))).to eq("No diff is available for this pair. One of the two snapshots is a report whose package database could not be read, so its package set is unknown. Showing every package as installed or removed would be wrong.")
      expect(page.css("#snapshot_picker select[name=to] option").map(&:text)).to include("2026-11-06 10:00 UTC (package database unreadable)")
    end

    it "says the packages are unknown when no readable report came before" do
      other = enrolled_host(name: "Other").first
      report_packages(other, [], manager: "unreadable", unsupported_reason: "no permission")
      get "/hosts/#{other.id}/packages"
      expect(page.at_css("#unreadable_packages strong").text).to eq("The agent could not read this host's package database, so its packages are unknown.")
      expect(words(page.at_css("#unreadable_packages p"))).to include("No earlier report could be read either.")
      expect(page.at_css("#package_list")).to be_nil
      expect(page.at_css("dl.facts dd .lamp").text).to eq("Unreadable")
      expect(page.css("nav.tabs a").map { |a| words(a) }).to include("Packages Unreadable")
      expect(words(page.at_css("#glance_packages"))).to eq("Packages Not known Package database could not be read")
      expect(page.css("#snapshot_list tbody tr td:nth-child(2)").map { |td| words(td) }).to eq([ "Oldest package snapshot kept, a package database that could not be read" ])
    end

    it "escapes the agent's reason (NFR-1)" do
      report([], at: start + 2.hours, manager: "unreadable", unsupported_reason: HOSTILE)
      get "/hosts/#{host.id}/packages"
      expect(page.css("script:not([nonce])")).to be_empty
      expect(page.css("img[onerror]")).to be_empty
      expect(page.at_css("#unreadable_packages .mono").text).to eq(HOSTILE)
    end
  end

  it "refuses another host's snapshot even with nothing to compare, and keeps the picker out of live refreshes" do
    other = enrolled_host.first
    report_packages(other, [ [ "bash", "5.2.37-1", "bash" ] ])
    get "/hosts/#{host.id}/packages/compare", params: { from: PackageSnapshot.find_by!(host: other).id }
    expect(response).to have_http_status(:not_found)
    report([ [ "bash", "5.2.37-1", "bash" ] ], at: start)
    report([ [ "bash", "5.2.37-2", "bash" ] ], at: start + 1.hour)
    get "/hosts/#{host.id}/packages/compare"
    expect(page.at_css("#snapshot_picker")["data-controller"]).to eq("keep-edits")
  end

  it "says there is nothing to compare with one snapshot or none" do
    get "/hosts/#{host.id}/packages/compare"
    expect(words(page.at_css("#nothing_to_compare"))).to start_with("No package report yet.")
    report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ])
    get "/hosts/#{host.id}/packages/compare"
    expect(words(page.at_css("#nothing_to_compare"))).to start_with("Only one package snapshot so far.")
  end
end
