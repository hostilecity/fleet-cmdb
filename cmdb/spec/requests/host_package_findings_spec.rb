require "rails_helper"

# The package page, paged and filtered (#283, a follow-up of VT-HOST-TAB #281): the tab's "N more" link carries its
# filters and the row's section, and lands on exactly the findings it counts; the filters are checked against fixed
# lists; text is escaped; the page reads the replica and sends a fixed number of statements. Package names and
# versions are a Debian 13 amd64 host's; advisory and CVE ids are made up.
RSpec.describe "Host package findings", :signed_in, type: :request do
  let(:local) { cvss("C:H/I:H/A:H") }

  # A local CVSS v3 vector (rule L2 with no signal): C:H/I:H/A:H is high, C:H/I:N/A:N medium, C:L/I:N/A:N low.
  def cvss(impact) = [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/#{impact}" } ]
  let(:running) { [ "linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64" ] }
  let(:packages) { [ running, [ "bash", "5.2.37-2", "bash" ], [ "curl", "8.14.1-2", "curl" ] ] }
  let(:host) { debian_host(name: "Media server", packages:).tap { |h| record_inventory(h, kernel_version: "6.12.48+deb13-amd64") } }
  let(:package_page) { "/hosts/#{host.id}/vulnerabilities/package" }

  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later)
    allow(CisEvaluationJob).to receive(:perform_later)
  end

  def words(node) = node&.xpath(".//text()")&.map(&:text)&.join(" ")&.squish
  RSpec::Matchers.define_negated_matcher :not_including, :include

  # The advisory ids of the package page's rows, in order.
  def page_ids = page.css("#package_findings tbody tr").map { |row| row.at_css("td:nth-child(2)").at_css("a, span.mono").text }

  # The advisory ids drawn under the tab's bash row in a table.
  def tab_ids(table) = page.css("##{table} > tbody:has(a[href$='package=bash']) .nested-findings tr.finding").map { |row| row.at_css("td:first-child").at_css("a, span.mono").text }

  # n bash advisories with no fix (L2: local, no signal), and one fixed kernel advisory per kernel entry, all at once.
  def import(bash: 0, kernel: 0)
    impacts = %w[C:H/I:H/A:H C:H/I:N/A:N C:L/I:N/A:N] # high, medium, low, in turn
    records = Array.new(bash) { |i| osv_record(id: "DEBIAN-CVE-2026-93#{format('%03d', i)}", package: "bash", fixed: nil, severity: cvss(impacts[i % 3])) }
    records += Array.new(kernel) { |i| osv_record(id: "DEBIAN-CVE-2026-91#{format('%03d', i)}", package: "linux", fixed: "6.12.57-1", severity: local) }
    import_advisories(*records, osv_record(id: "DEBIAN-CVE-2026-94001", package: "curl", fixed: nil, severity: local), full: true)
    VulnerabilityMatcher.match!([ host.id ])
  end

  it "lands the tab's \"N more\" link on exactly the findings the row counts, after the ones it drew, with the tab's filters" do
    stub_const("HostTriageSections::NESTED_MAX", 2)
    import(bash: 6)
    # The sixth resolves (as a withdrawal would): the package page still lists it unfiltered, never with the tab's filters.
    VulnerabilityFinding.joins(:advisory).where(host:, advisories: { advisory_id: "DEBIAN-CVE-2026-93005" })
                        .update_all(state: "resolved", resolution: "withdrawn", resolved_at: Time.current, bucket: nil, bucket_rule: nil, kev: nil)
    get "/hosts/#{host.id}/vulnerabilities", params: { rule: "L2", severity: "high" }
    row = page.at_css("#rule_list > tbody:has(a[href$='package=bash'])")
    expect(tab_ids("rule_list").size).to eq(2)
    # The row counts the open bash findings in rule L2 that are high: the 0th and 3rd (severities cycle high, medium, low).
    counted = VulnerabilityFinding.joins(:advisory).where(host:, package: "bash", state: %w[open reopened], bucket_rule: VulnerabilityTriage::RULE_IDS.fetch("L2"),
                                                          advisories: { severity: "high" }).count
    expect(counted).to eq(2)
    expect(row.at_css("tr.more")).to be_nil # two high ones, both drawn

    get "/hosts/#{host.id}/vulnerabilities", params: { rule: "L2" }
    row = page.at_css("#rule_list > tbody:has(a[href$='package=bash'])")
    shown = tab_ids("rule_list")
    expect(words(row.at_css("tr.more"))).to start_with("Open the package page : 3 more findings here match. The first 2 are shown")
    link = row.at_css("tr.more a")["href"]
    expect(Rack::Utils.parse_query(URI(link).query).except("after")).to eq("package" => "bash", "arch" => "amd64", "state" => "open", "section" => "rule", "rule" => "L2", "from" => "tab")

    get link
    expect(response).to have_http_status(:ok)
    rest = page_ids
    expect(rest.size).to eq(3)
    expect(rest & shown).to be_empty
    l2 = VulnerabilityFinding.joins(:advisory).where(host:, package: "bash", state: %w[open reopened], bucket_rule: VulnerabilityTriage::RULE_IDS.fetch("L2"))
    expect(shown + rest).to match_array(l2.pluck("advisories.advisory_id"))
    expect(words(page.at_css("#package_filters"))).to eq("5 findings of the package's 6 match: open and reopened, rule L2 (Low risk), architecture amd64. Show every finding of this package")
    expect(words(page.at_css("#package_findings_pager"))).to start_with("Previous").and include("3 findings shown of 5. Worst severity first, then the earliest first seen.")
    expect(words(page.at_css("#package_from_tab"))).to eq("Starting after the first 2 findings, which the Vulnerabilities tab shows under this package's row.") # N1
    expect(page.css("#package_findings tbody tr td:last-child").map { |td| words(td) }).to all(start_with("Low risk").and(end_with("L2")))

    # Previous: the first page, which starts with the ones the tab drew, in the tab's order.
    get page.at_css("#package_findings_pager a[rel=prev]")["href"]
    expect(page_ids).to eq(shown + rest)
    expect(page.at_css("#package_findings_pager a[rel=prev]")).to be_nil

    # With the tab's other filters too: the link keeps them, and the page applies them.
    get "/hosts/#{host.id}/vulnerabilities", params: { rule: "L2", severity: "medium", q: "bash" }
    link = page.at_css("#rule_list tr.more a")
    expect(link).to be_nil # two medium ones: drawn whole
    stub_const("HostTriageSections::NESTED_MAX", 1)
    get "/hosts/#{host.id}/vulnerabilities", params: { rule: "L2", severity: "medium", q: "bash" }
    link = page.at_css("#rule_list tr.more a")["href"]
    expect(Rack::Utils.parse_query(URI(link).query)).to include("severity" => "medium", "q" => "bash")
    get link
    expect(page_ids.size).to eq(1)
    expect(words(page.at_css("#package_filters"))).to start_with("2 findings of the package's 6 match: open and reopened, rule L2 (Low risk), architecture amd64, severity medium, matching “bash”.")

    # Unfiltered, as the package rows' own links open it: every finding, in every state.
    get package_page, params: { package: "bash" }
    expect(page.at_css("#package_filters")).to be_nil
    expect(page_ids.size).to eq(6)
    expect(page.css("#package_findings tbody tr td:last-child").map { |td| words(td) }).to include("Resolved: in no bucket")
    expect(words(page.at_css("#package_summary p"))).to eq("5 open , 1 resolved .")
  end

  it "keeps the kernel's rows and the not-triaged rows apart in their links" do
    stub_const("HostTriageSections::NESTED_MAX", 1)
    import(bash: 2, kernel: 3)
    get "/hosts/#{host.id}/vulnerabilities"
    link = page.at_css("#kernel_list tr.more a")["href"]
    expect(Rack::Utils.parse_query(URI(link).query)).to include("section" => "kernel", "package" => running.first, "state" => "open")
    get link
    expect(page_ids.size).to eq(2)
    expect(page.css("#package_findings tbody tr td:last-child").map { |td| words(td) }).to all(start_with("Fix available").and(end_with("K2")))
    expect(words(page.at_css("#package_filters"))).to include("Fix available, the kernel's steps (K1, K2)")
    get package_page, params: { package: running.first, state: "open", section: "fix" }
    expect(page.at_css("#package_no_match")).not_to be_nil # no package-upgrade finding (F1, F2) for the kernel image

    VulnerabilityFinding.where(host:, package: "bash").update_all(bucket: nil, bucket_rule: nil, kev: nil)
    get "/hosts/#{host.id}/vulnerabilities"
    link = page.at_css("#untriaged_list tr.more a")["href"]
    expect(Rack::Utils.parse_query(URI(link).query)).to include("section" => "untriaged", "package" => "bash")
    get link
    expect(page_ids.size).to eq(1)
    expect(words(page.at_css("#package_findings tbody td:last-child"))).to eq("Not triaged yet.")
  end

  it "pages by keyset on the whole sort key, and says why when a link does not parse or nothing is left past it" do
    stub_const("HostPackageFindings::PER_PAGE", 2)
    import(bash: 5)
    get package_page, params: { package: "bash" }
    first = page_ids
    expect(first.size).to eq(2)
    expect(words(page.at_css("#package_findings_pager"))).to eq("Previous 2 findings shown of 5. Worst severity first, then the earliest first seen. Next")
    get page.at_css("#package_findings_pager a[rel=next]")["href"]
    second = page_ids
    get page.at_css("#package_findings_pager a[rel=next]")["href"]
    third = page_ids
    expect(page.at_css("#package_findings_pager a[rel=next]")).to be_nil
    expect((first + second + third).uniq.size).to eq(5)
    # Worst severity first: high, high, medium, medium, low.
    expect(VulnerabilityFinding.joins(:advisory).where(host:, package: "bash").pluck("advisories.advisory_id", "advisories.severity").to_h.values_at(*first, *second, *third))
      .to eq(%w[high high medium medium low])
    get page.at_css("#package_findings_pager a[rel=prev]")["href"]
    expect(page_ids).to eq(second)
    get page.at_css("#package_findings_pager a[rel=prev]")["href"]
    expect(page_ids).to eq(first)

    [ "x,y", "9,2026-11-01T00:00:00Z,DEBIAN-CVE-1,1", "1,not-a-time,DEBIAN-CVE-1,1", "1,2026-11-01T00:00:00Z,a b,1", "x" * 201 ].each do |cursor|
      get package_page, params: { package: "bash", after: cursor }
      expect(words(page.at_css("#package_page_notice"))).to eq("The page link is not one this page wrote, so the first page is shown. Go to the first page")
      expect(page_ids).to eq(first)
    end
    get package_page, params: { package: "bash", state: "open", after: "5,2099-01-01T00:00:00.000000Z,DEBIAN-CVE-ZZZ,1" }
    expect(words(page.at_css("#package_page_notice"))).to start_with("The findings changed since this page was opened, and none are left past it")
    expect(page.at_css("#package_page_notice a")["href"]).to eq("#{package_page}?package=bash&state=open")
    expect(page_ids).to eq(first)
  end

  it "keeps only the tab's values for each filter, and escapes the text search" do
    import(bash: 3)
    get package_page, params: { package: "bash", state: "evil", severity: "<b>", signal: "x", section: "../x", rule: "K1", arch: "amd64 OR 1=1", debian: "y", fix: "1" }
    expect(response).to have_http_status(:ok)
    expect(page.at_css("#package_filters")).to be_nil
    expect(page_ids.size).to eq(3)
    # An architecture the package does not have is dropped, not echoed (N4); from=tab says nothing without a cursor.
    get package_page, params: { package: "bash", arch: "i386", from: "tab" }
    expect(page.at_css("#package_filters")).to be_nil
    expect(page.at_css("#package_from_tab")).to be_nil
    expect(response.body).not_to include("i386")
    get package_page, params: { package: "bash", state: "open", section: "rule", rule: "K1" } # not a Low risk or Ignorable rule: no section
    expect(words(page.at_css("#package_filters"))).to eq("3 findings of the package's 3 match: open and reopened. Show every finding of this package")
    get package_page, params: { package: "bash", state: "resolved", section: "untriaged", debian: "no_dsa", fix: "available" } # open-only filters, ignored
    expect(words(page.at_css("#package_filters"))).to start_with("0 findings of the package's 3 match: resolved.")
    expect(page.at_css("#package_no_match")).not_to be_nil

    get package_page, params: { package: "bash", state: "open", q: "<script>alert(1)</script>‮" }
    expect(response.body).not_to include("<script>alert(1)</script>")
    expect(page.css("#package_filters script")).to be_empty
    expect(page.at_css("#package_filters").text).to include("matching “<script>alert(1)</script>‮”")
    get package_page, params: { package: "bash", q: "x" * 500 }
    expect(page.at_css("#package_filters").text).to include("x" * HostVulnerabilitiesController::QUERY_MAX)
    expect(page.at_css("#package_filters").text).not_to include("x" * (HostVulnerabilitiesController::QUERY_MAX + 1))
  end

  it "reads the replica and sends the same statements whatever the package's number of findings" do
    stub_const("HostPackageFindings::PER_PAGE", 2)
    stub_const("HostTriageSections::NESTED_MAX", 1)
    statements = lambda do |path, **params|
      sql = []
      counter = ->(*, payload) { sql << payload[:sql] unless payload[:name] == "SCHEMA" || payload[:sql].match?(/\A(SET|BEGIN|COMMIT|ROLLBACK)\b/) }
      ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { get path, params: }
      expect(response).to have_http_status(:ok)
      sql.size
    end
    import(bash: 3)
    get "/hosts/#{host.id}/vulnerabilities", params: { rule: "L2" }
    more = page.at_css("#rule_list tr.more a")["href"]
    cases = [ [ package_page, { package: "bash" } ], [ package_page, { package: "bash", state: "open", severity: "high", signal: "network", q: "bash" } ], [ more, {} ] ]
    before = cases.map { |path, params| statements.call(path, **params) }
    import(bash: 60)
    expect(cases.map { |path, params| statements.call(path, **params) }).to eq(before)

    roles = []
    callback = ->(*, payload) { roles << ApplicationRecord.current_role if payload[:sql].include?("AS severity_rank") }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { get more }
    expect(roles).to eq([ :reading ]) # #237: the page reads a caught-up replica when one is configured
  end

  it "probes no finding's verdict one at a time on the tab or the package page, filtered or not (#302)" do
    import(bash: 8, kernel: 3)
    # Still affected at a newer version: no finding row is written, so only the verdict, the page rows' details, has it.
    report_packages(host, [ running, [ "bash", "5.2.37-3", "bash" ], [ "curl", "8.14.1-2", "curl" ] ])
    VulnerabilityMatcher.match!([ host.id ])
    expect(VulnerabilityFinding.where(host:, package: "bash").distinct.pluck(:last_installed_version)).to eq([ "5.2.37-2" ])
    probes = []
    callback = ->(*, payload) { probes << payload[:sql] if payload[:sql].include?("LEFT JOIN LATERAL ( SELECT m.source") }
    tab = "/hosts/#{host.id}/vulnerabilities"
    paths = [ [ tab, {} ], [ tab, { rule: "L2" } ], [ tab, { state: "all" } ], [ tab, { q: "bash" } ], [ tab, { debian: "no_dsa" } ], [ tab, { bucket: "fix" } ],
              [ package_page, { package: "bash" } ], [ package_page, { package: "bash", q: "bash", state: "open", section: "rule", rule: "L2" } ],
              [ package_page, { package: running.first } ] ]
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") do
      paths.each do |path, params|
        get(path, params:)
        expect(response).to have_http_status(:ok)
      end
    end
    expect(probes).to be_empty
    get tab, params: { rule: "L2" }
    expect(words(page.at_css("#rule_list > tbody:has(a[href$='package=bash'])"))).to include("5.2.37-3").and(not_including("5.2.37-2"))
    get package_page, params: { package: "bash" }
    expect(words(page.at_css("#package_findings"))).to include("5.2.37-3").and(not_including("5.2.37-2"))
    get package_page, params: { package: "bash", q: "bash" }
    expect(page_ids.size).to eq(8) # the text search still reads the source, through the host's verdicts
  end

  it "shows a page's rows worst first, then the earliest first seen, then the advisory id (review of #315, N1)" do
    stub_const("HostPackageFindings::PER_PAGE", 3)
    import(bash: 6) # 93000 and 93003 high, 93001 and 93004 medium, 93002 and 93005 low
    # The later advisory id first seen earlier: first seen, not the id, puts it first.
    VulnerabilityFinding.joins(:advisory).where(host:, advisories: { advisory_id: "DEBIAN-CVE-2026-93003" }).update_all(first_seen_at: 2.days.ago)
    VulnerabilityFinding.joins(:advisory).where(host:, advisories: { advisory_id: "DEBIAN-CVE-2026-93004" }).update_all(first_seen_at: 2.days.ago)
    get package_page, params: { package: "bash" }
    expect(page_ids).to eq(%w[DEBIAN-CVE-2026-93003 DEBIAN-CVE-2026-93000 DEBIAN-CVE-2026-93004])
    get package_page, params: { package: "bash", after: page.at_css("a[rel=next]")&.[]("href").to_s[/after=([^&]+)/, 1].then { CGI.unescape(_1.to_s) } }
    expect(page_ids).to eq(%w[DEBIAN-CVE-2026-93001 DEBIAN-CVE-2026-93002 DEBIAN-CVE-2026-93005])
  end

  describe "the paths that make the counts exact (review of #297, S2)" do
    let(:network) { cvss("C:H/I:H/A:H").map { |v| v.merge("score" => v["score"].sub("AV:L/AC:L/PR:L", "AV:N/AC:L/PR:N")) } }

    def link_query(href) = Rack::Utils.parse_query(URI(href).query)

    def reasons = page.css("#package_findings tbody tr td:last-child").map { |td| words(td) }

    it "lands on one architecture's rest only, and pages across two architectures' ties without skipping or repeating" do
      host = debian_host(name: "Multiarch", hostname: "vm-03.example.lan",
                         packages: [ [ "libc6", "2.41-12", "glibc", "amd64" ], [ "libc6", "2.41-12", "glibc", "i386" ], [ "bash", "5.2.37-2", "bash" ] ])
      import_advisories(*Array.new(3) { |i| osv_record(id: "DEBIAN-CVE-2026-96#{format('%03d', i)}", package: "glibc", fixed: nil, severity: local) }, full: true)
      VulnerabilityMatcher.match!([ host.id ])
      # One matching run: the same advisory on both architectures has the same first seen, so they tie on all but the id.
      expect(VulnerabilityFinding.where(host:, package: "libc6").group(:advisory_id).distinct.count(:first_seen_at).values).to all(eq(1))
      stub_const("HostTriageSections::NESTED_MAX", 1)
      get "/hosts/#{host.id}/vulnerabilities", params: { rule: "L2" }
      row = page.css("#rule_list > tbody").find { |body| body.at_css("tr.pkg-group th a").text == "libc6:amd64" }
      expect(words(row.at_css("tr.more"))).to start_with("Open the package page : 2 more findings here match.")
      get row.at_css("tr.more a")["href"]
      expect(page.css("#package_findings tbody tr td:nth-child(3)").map { |td| words(td) }).to eq([ "libc6:amd64" ] * 2)

      stub_const("HostPackageFindings::PER_PAGE", 1)
      get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "libc6" }
      seen = []
      10.times do # at most 10 pages, so a cursor that never moves fails rather than loops
        seen << [ page_ids.sole, words(page.at_css("#package_findings tbody td:nth-child(3)")) ]
        following = page.at_css("#package_findings_pager a[rel=next]") or break
        get following["href"]
      end
      expect(seen.size).to eq(6)
      expect(seen.uniq.size).to eq(6)
    end

    it "orders advisory ids bytewise, as the tab does, whatever the database's collation" do
      # The column gets a collation that sorts "a" before "B" (ICU's root, in PostgreSQL's ICU builds, CI's included);
      # the page's key keeps "C", so a cursor from the tab (Ruby's bytewise order) still finds the rest. Rolled back.
      ActiveRecord::Base.connection.execute('ALTER TABLE advisories ALTER COLUMN advisory_id TYPE varchar(128) COLLATE "und-x-icu"')
      ActiveRecord::Base.connection.clear_cache! # prepared statements over the old column type
      expect(ActiveRecord::Base.connection.select_value(%q(SELECT 'a' < 'B' COLLATE "und-x-icu"))).to be(true)
      stub_const("HostTriageSections::NESTED_MAX", 1)
      import_advisories(*%w[DEBIAN-CVE-2026-B1 DEBIAN-CVE-2026-a1].map { |id| osv_record(id:, package: "bash", fixed: nil, severity: local) }, full: true)
      VulnerabilityMatcher.match!([ host.id ])
      get "/hosts/#{host.id}/vulnerabilities", params: { rule: "L2" }
      expect(tab_ids("rule_list")).to eq([ "DEBIAN-CVE-2026-B1" ])
      get page.at_css("#rule_list tr.more a")["href"]
      expect(page.at_css("#package_page_notice")).to be_nil
      expect(page_ids).to eq([ "DEBIAN-CVE-2026-a1" ])
      # And the page's own order and cursors are bytewise too: one a page, B1 then a1, neither skipped nor shown twice.
      stub_const("HostPackageFindings::PER_PAGE", 1)
      get package_page, params: { package: "bash" }
      expect(page_ids).to eq([ "DEBIAN-CVE-2026-B1" ])
      get page.at_css("#package_findings_pager a[rel=next]")["href"]
      expect(page.at_css("#package_page_notice")).to be_nil
      expect(page_ids).to eq([ "DEBIAN-CVE-2026-a1" ])
    ensure
      # Back before the rollback, and no prepared statement over the ICU column left for the next example.
      ActiveRecord::Base.connection.execute('ALTER TABLE advisories ALTER COLUMN advisory_id TYPE varchar(128) COLLATE "default"')
      ActiveRecord::Base.connection.clear_cache!
    end

    it "lands the not-triaged row's link on the untriaged findings only, beside triaged ones of the same package" do
      stub_const("HostTriageSections::NESTED_MAX", 1)
      import(bash: 5) # high, medium, low, high, medium
      VulnerabilityFinding.joins(:advisory).where(host:, advisories: { advisory_id: %w[DEBIAN-CVE-2026-93000 DEBIAN-CVE-2026-93001 DEBIAN-CVE-2026-93002] })
                          .update_all(bucket: nil, bucket_rule: nil, kev: nil)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#untriaged_list > tbody:has(a[href$='package=bash']) tr.more"))).to start_with("Open the package page : 2 more findings here match.")
      get page.at_css("#untriaged_list > tbody:has(a[href$='package=bash']) tr.more a")["href"]
      expect(page_ids).to eq(%w[DEBIAN-CVE-2026-93001 DEBIAN-CVE-2026-93002])
      expect(reasons).to eq([ "Not triaged yet." ] * 2)
    end

    it "carries the tab's signal, Debian, and fix filters through the link, and applies each" do
      stub_const("HostTriageSections::NESTED_MAX", 1)
      # 93000 to 93002 match all three; each of the others misses one: 93003 the signal, 93004 the fix, 93005 Debian's note.
      shapes = { 0 => [ network, "5.2.37-3", true ], 1 => [ network, "5.2.37-3", true ], 2 => [ network, "5.2.37-3", true ],
                 3 => [ local, "5.2.37-3", true ], 4 => [ network, nil, true ], 5 => [ network, "5.2.37-3", false ] }
      import_advisories(*shapes.map { |i, (severity, fixed, _)| osv_record(id: "DEBIAN-CVE-2026-93#{format('%03d', i)}", package: "bash", fixed:, severity:) }, full: true)
      import_triage(tracker_document("bash" => shapes.select { |_, (_, _, nodsa)| nodsa }.to_h do |i, _|
        [ "CVE-2026-93#{format('%03d', i)}", { "trixie" => tracker_release(nodsa: "Minor issue") } ]
      end))
      VulnerabilityMatcher.match!([ host.id ])
      VulnerabilityFinding.where(host:).update_all(bucket: nil, bucket_rule: nil, kev: nil) # one section holds them all
      get "/hosts/#{host.id}/vulnerabilities", params: { signal: "network", debian: "no_dsa", fix: "available" }
      row = page.at_css("#untriaged_list > tbody:has(a[href$='package=bash'])")
      expect(words(row.at_css("tr.more"))).to start_with("Open the package page : 2 more findings here match.")
      expect(link_query(row.at_css("tr.more a")["href"])).to include("signal" => "network", "debian" => "no_dsa", "fix" => "available", "section" => "untriaged")
      get row.at_css("tr.more a")["href"]
      expect(page_ids).to eq(%w[DEBIAN-CVE-2026-93001 DEBIAN-CVE-2026-93002])
      expect(words(page.at_css("#package_filters"))).to start_with("3 findings of the package's 6 match: open and reopened, not triaged yet, architecture amd64, " \
                                                                   "signal: network, no login, no user action, Debian: no security update planned, the advisory data names a fix.")
    end

    # A resolved package row (#303): a removed kernel image leaves every finding it had under one row of the resolved list.
    def resolve(*ids)
      VulnerabilityFinding.joins(:advisory).where(host:, advisories: { advisory_id: ids.map { |i| "DEBIAN-CVE-2026-93#{format('%03d', i)}" } })
                          .update_all(state: "resolved", resolution: "removed", resolved_at: Time.current, bucket: nil, bucket_rule: nil, kev: nil)
    end

    it "caps a resolved row too, landing its link on exactly the resolved findings it counts, with the tab's filters (#303)" do
      stub_const("HostTriageSections::NESTED_MAX", 1)
      # 93000 to 93003 on the network, 93004 and 93005 local; all but 93003 and 93005 resolve.
      import_advisories(*Array.new(6) { |i| osv_record(id: "DEBIAN-CVE-2026-93#{format('%03d', i)}", package: "bash", fixed: nil, severity: i < 4 ? network : local) }, full: true)
      VulnerabilityMatcher.match!([ host.id ])
      resolve(0, 1, 2, 4)
      get "/hosts/#{host.id}/vulnerabilities", params: { state: "resolved" }
      row = page.at_css("#resolved_list > tbody:has(a[href$='package=bash'])")
      shown = tab_ids("resolved_list")
      expect(shown.size).to eq(1)
      expect(words(row.at_css("tr.more"))).to eq("Open the package page : 3 more findings here match. The first 1 are shown, worst severity first; " \
                                                 "the package page lists the rest with the same filters, in pages.")
      expect(link_query(row.at_css("tr.more a")["href"]).except("after")).to eq("package" => "bash", "arch" => "amd64", "state" => "resolved", "from" => "tab")
      get row.at_css("tr.more a")["href"]
      rest = page_ids
      expect(rest.size).to eq(3)
      expect(shown + rest).to match_array(%w[DEBIAN-CVE-2026-93000 DEBIAN-CVE-2026-93001 DEBIAN-CVE-2026-93002 DEBIAN-CVE-2026-93004])
      expect(reasons).to all(eq("Resolved: in no bucket"))
      expect(words(page.at_css("#package_filters"))).to eq("4 findings of the package's 6 match: resolved, architecture amd64. Show every finding of this package")
      expect(words(page.at_css("#package_from_tab"))).to eq("Starting after the first 1 findings, which the Vulnerabilities tab shows under this package's row.")

      # Under "All" the tab's signal narrows the resolved list too: the link carries it, and the page applies it, so the
      # local 93004 is in neither.
      get "/hosts/#{host.id}/vulnerabilities", params: { state: "all", signal: "network", severity: "critical", q: "bash" }
      row = page.at_css("#resolved_list > tbody:has(a[href$='package=bash'])")
      shown = tab_ids("resolved_list")
      expect(words(row.at_css("tr.more"))).to start_with("Open the package page : 2 more findings here match.")
      expect(link_query(row.at_css("tr.more a")["href"]).except("after")).to eq("package" => "bash", "arch" => "amd64", "state" => "resolved", "signal" => "network",
                                                                               "severity" => "critical", "q" => "bash", "from" => "tab")
      get row.at_css("tr.more a")["href"]
      expect(shown + page_ids).to match_array(%w[DEBIAN-CVE-2026-93000 DEBIAN-CVE-2026-93001 DEBIAN-CVE-2026-93002])
      expect(words(page.at_css("#package_filters"))).to start_with("3 findings of the package's 6 match: resolved, architecture amd64, severity critical, " \
                                                                   "signal: network, no login, no user action, matching “bash”.")
    end

    it "draws a resolved row in the same statements whatever its number of findings, from the replica (#303)" do
      stub_const("HostTriageSections::NESTED_MAX", 1)
      statements = lambda do |path, **params|
        sql = []
        counter = ->(*, payload) { sql << payload[:sql] unless payload[:name] == "SCHEMA" || payload[:sql].match?(/\A(SET|BEGIN|COMMIT|ROLLBACK)\b/) }
        ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { get path, params: }
        expect(response).to have_http_status(:ok)
        sql.size
      end
      import(bash: 3)
      VulnerabilityFinding.where(host:, package: "bash").update_all(state: "resolved", resolution: "removed", resolved_at: Time.current, bucket: nil, bucket_rule: nil, kev: nil)
      tab = "/hosts/#{host.id}/vulnerabilities"
      more = -> { get(tab, params: { state: "resolved" }) && page.at_css("#resolved_list tr.more a")["href"] }
      cases = [ [ tab, { state: "resolved" } ], [ tab, { state: "all", q: "bash" } ], [ more.call, {} ] ]
      before = cases.map { |path, params| statements.call(path, **params) }
      import(bash: 60)
      VulnerabilityFinding.where(host:, package: "bash").update_all(state: "resolved", resolution: "removed", resolved_at: Time.current, bucket: nil, bucket_rule: nil, kev: nil)
      expect(cases.map { |path, params| statements.call(path, **params) }).to eq(before)
      get tab, params: { state: "resolved" }
      expect(words(page.at_css("#resolved_list > tbody:has(a[href$='package=bash']) tr.more"))).to start_with("Open the package page : 59 more findings here match.")

      roles = []
      callback = ->(*, payload) { roles << ApplicationRecord.current_role if payload[:name] == "HostFindingGroups" }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { get tab, params: { state: "resolved" } }
      expect(roles).to eq([ :reading ]) # #198: the tab reads a caught-up replica when one is configured
    end

    it "gives a reason that needs the KEV date its date" do
      import_kev(kev_file("CVE-2026-93000"))
      import(bash: 1)
      get package_page, params: { package: "bash" }
      expect(reasons.sole).to start_with("Needs attention").and include("On CISA's Known Exploited Vulnerabilities list since 2026-11-02 (CVE-2026-93000).").and end_with("N1")
    end
  end
end
