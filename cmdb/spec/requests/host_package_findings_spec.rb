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

  # The advisory ids of the package page's rows, in order.
  def page_ids = page.css("#package_findings tbody tr").map { |row| row.at_css("td:nth-child(2)").text[/DEBIAN-CVE-\d+-\d+/] }

  # The advisory ids drawn under the tab's bash row in a table.
  def tab_ids(table) = page.css("##{table} > tbody:has(a[href$='package=bash']) .nested-findings tr.finding").map { |row| row.text[/DEBIAN-CVE-\d+-\d+/] }

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
    expect(Rack::Utils.parse_query(URI(link).query).except("after")).to eq("package" => "bash", "arch" => "amd64", "state" => "open", "section" => "rule", "rule" => "L2")

    get link
    expect(response).to have_http_status(:ok)
    rest = page_ids
    expect(rest.size).to eq(3)
    expect(rest & shown).to be_empty
    l2 = VulnerabilityFinding.joins(:advisory).where(host:, package: "bash", state: %w[open reopened], bucket_rule: VulnerabilityTriage::RULE_IDS.fetch("L2"))
    expect(shown + rest).to match_array(l2.pluck("advisories.advisory_id"))
    expect(words(page.at_css("#package_filters"))).to eq("5 findings of the package's 6 match: open and reopened, rule L2 (Low risk), architecture amd64. Show every finding of this package")
    expect(words(page.at_css("#package_findings_pager"))).to start_with("Previous").and include("3 findings shown of 5. Worst severity first, then the earliest first seen.")
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
    get package_page, params: { package: "bash", state: "open", section: "rule", rule: "K1" } # not a Low risk or Ignorable rule: no section
    expect(words(page.at_css("#package_filters"))).to eq("3 findings of the package's 3 match: open and reopened. Show every finding of this package")
    get package_page, params: { package: "bash", state: "resolved", section: "untriaged", signal: "kev", fix: "available" } # open-only filters, ignored
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
end
