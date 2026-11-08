require "rails_helper"
require "benchmark"

# The fleet compliance view (P2-D05, FR-2.5; approved mockup compliance.html, owner decisions Q8 to Q10).
RSpec.describe "Compliance", :signed_in, type: :request do
  def words(node) = node.text.squish

  # A cell's text with its parts (spans, lines) apart.
  def cell_words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  def row_names = page.css("#compliance_table tbody th[scope=row] > a").map(&:text)

  def row_cells(host) = page.css("tr#compliance_host_#{host.id} td").map { |td| cell_words(td) }

  def query(link) = Rack::Utils.parse_query(URI(link["href"]).query)

  def strip(id) = page.css("##{id} .sevstrip a").map { |a| [ words(a.at_css(".sev")), a.at_css(".count").text.to_i ] }.to_h

  it "is a top-level navigation item after Fleet, current on its page (Q10)" do
    get "/compliance"
    expect(response).to have_http_status(:ok)
    nav = page.css("nav[aria-label=Main] a")
    expect(nav.map(&:text).first(2)).to eq(%w[Fleet Compliance])
    expect(page.at_css("nav[aria-label=Main] a[aria-current=page]").text).to eq("Compliance")
    get "/"
    expect(page.at_css("nav[aria-label=Main] a[aria-current=page]").text).to eq("Fleet")
  end

  it "has the mockup's Data sources button, and the navigation lists Rules and Data sources after Compliance (P2-D06)" do
    get "/compliance"
    expect(page.at_css(".page-head #data_sources_link")).to have_attributes(text: "Data sources")
    expect(page.at_css(".page-head #data_sources_link")["href"]).to eq("/data-sources")
    expect(page.css("nav[aria-label=Main] a").map(&:text).first(4)).to eq([ "Fleet", "Compliance", "Rules", "Data sources" ])
  end

  it "says there are no active hosts, with the way to add one, and draws no counts" do
    create(:host, name: "Lab sandbox")
    get "/compliance"
    expect(words(page.at_css("#no_active_hosts"))).to start_with("No active hosts to show.")
    expect(page.at_css("#no_active_hosts a")["href"]).to eq("/agents/install")
    expect(page.css(".sevstrip, #compliance_table")).to be_empty
    expect(words(page.at_css(".page-head p"))).to include("for the 0 active hosts")
    expect(page.css(".page-head .actions a").map { |a| [ a.text, a["href"] ] }).to eq([ [ "Manage rules", "/rules" ], [ "Data sources", "/data-sources" ] ]) # P2-D06
  end

  context "with a fleet" do
    let!(:rules) { compliance_rules(3).values.flatten }

    def results(host, **named)
      by_key = named.flat_map { |result, keys| Array(keys).map { |key| [ key.to_s, result.to_s ] } }.to_h
      cis_results!(host, rules.to_h { |r| [ r, by_key.fetch(r.key, "pass") ] })
    end

    let!(:build) { enrolled_host(name: "Build runner", tags: %w[ci]).first }
    let!(:web) { enrolled_host(name: "Web A", tags: %w[web lab]).first }
    let!(:backup) { enrolled_host(name: "Backup target", tags: %w[storage]).first }
    let!(:dns) { enrolled_host(name: "DNS resolver", tags: %w[infra]).first }
    let!(:retired) { create(:host, :retired, name: "Gone") }

    before do
      record_heartbeat(web)
      results(build, fail: %w[critical-0 high-0 medium-0 low-0], not_readable: %w[medium-1])
      host_config!(build, at: 5.hours.ago)
      record_inventory(build)
      results(web, fail: %w[medium-0 low-0])
      host_config!(web, at: 2.hours.ago)
      package_set!(web, at: 2.hours.ago)
      vulns_evaluated!(web)
      findings!(web, "critical", "low")
      results(backup)
      host_config!(backup)
      package_set!(backup)
      vulns_evaluated!(backup)
      findings!(backup, "high", state: "resolved")
      results(retired, fail: %w[critical-0])
    end

    it "shows the fleet-wide open counts by severity, each linking to the hosts behind it" do
      get "/compliance"
      expect(strip("cis_totals")).to eq("Critical" => 1, "High" => 1, "Medium" => 2, "Low" => 2)
      expect(strip("vuln_totals")).to eq("Critical" => 1, "High" => 0, "Medium" => 0, "Low" => 1, "Unknown" => 0)
      expect(page.css("#cis_totals .sevstrip a").map { |a| a["href"] }).to eq(%w[critical high medium low].map { |s| "/compliance?cis=#{s}" })
      expect(page.css("#vuln_totals .sevstrip a").map { |a| a["href"] }).to eq(%w[critical high medium low unknown].map { |s| "/compliance?vuln=#{s}" })
      expect(words(page.at_css("#cis_totals .strip-title .muted"))).to eq("3 of 4 hosts evaluated. Not evaluated hosts are not counted.")
      expect(words(page.at_css("#fleet_pass_rate"))).to eq("Fleet pass rate: 80.6%, 29 of 36 checks pass on the 3 hosts evaluated.")
      expect(words(page.at_css("#vuln_totals .strip-title .muted"))).to eq("2 of 4 hosts evaluated. 2 hosts are not evaluated: see which and why.")
      expect(page.at_css("#vuln_totals .strip-title a")["href"]).to eq("/compliance?status=not_evaluated")
    end

    it "makes each fleet-wide count the sum of the table's column" do
      get "/compliance"
      # Columns after the pass rate: four CIS severities, then five vulnerability severities. A cell spanning several says
      # none open or not evaluated, and adds nothing.
      sums = Array.new(9, 0)
      page.css("#compliance_table tbody tr").each do |tr|
        grid = tr.css("td").flat_map { |td| [ td.css(".not-eval, .none-open").any? ? 0 : td.text.to_i ] * (td["colspan"] || 1).to_i }
        grid[1, 9].each_with_index { |value, i| sums[i] += value }
      end
      expect(strip("cis_totals").values).to eq(sums.first(4))
      expect(strip("vuln_totals").values).to eq(sums.last(5))
      expect(sums).to eq([ 1, 1, 2, 2, 1, 0, 0, 1, 0 ])
    end

    it "lists every active host worst first, with not evaluated, none open, and a grey zero drawn three different ways" do
      travel_to(Time.current) { get "/compliance" }
      expect(row_names).to eq([ "Build runner", "Web A", "Backup target", "DNS resolver" ])
      expect(response.body).not_to include("Gone")

      build_row = page.at_css("tr#compliance_host_#{build.id}")
      expect(row_cells(build)).to eq([ "58.3% passes 7 of 12 checks", "1", "1", "1", "1", "Not evaluated No package report yet", "Config about 5 hours ago Packages never" ])
      expect(build_row.css("td.sevcount.hot").map(&:text)).to eq(%w[1 1])
      expect(build_row.at_css("td[colspan='5'] .not-eval")).to be_present
      expect(build_row.at_css("th .lamp").text).to eq("Awaiting first contact")
      expect(build_row.at_css("th a.tag")["href"]).to eq("/compliance?tag=ci")

      expect(row_cells(web)).to eq([ "83.3% passes 10 of 12 checks", "0", "0", "1", "1", "1", "0", "0", "1", "0", "Config about 2 hours ago Packages about 2 hours ago" ])
      zero = page.css("tr#compliance_host_#{web.id} td.sevcount.zero")
      expect(zero.size).to eq(5)
      expect(zero.map(&:text).uniq).to eq([ "0" ])

      backup_row = page.at_css("tr#compliance_host_#{backup.id}")
      expect(row_cells(backup)).to eq([ "100% passes 12 of 12 checks", "None open", "None open", "Config about 1 hour ago Packages about 1 hour ago" ])
      expect(backup_row.css(".none-open").size).to eq(2)
      expect(backup_row.css(".not-eval, td.sevcount")).to be_empty
      expect(backup_row["class"]).not_to include("not-evaluated")

      dns_row = page.at_css("tr#compliance_host_#{dns.id}")
      expect(dns_row["class"]).to include("not-evaluated")
      expect(row_cells(dns)).to eq([ "Not evaluated No config report yet", "Not evaluated No inventory yet, so the distribution is not known", "Never" ])
      expect(dns_row.css(".none-open, td.sevcount, .meter")).to be_empty
      expect(dns_row.text).not_to match(/\b0%|\b0\b/)
      expect(words(page.at_css("#compliance_pager"))).to eq("4 of 4 active hosts.")
    end

    it "says why vulnerabilities are not evaluated, and keeps findings from an earlier evaluation" do
      vulns_evaluated!(dns, state: "not_evaluated", reason: "no_advisory_data")
      old = enrolled_host(name: "Old findings").first
      vulns_evaluated!(old, state: "not_evaluated", reason: "unsupported_package_manager")
      findings!(old, "high")
      get "/compliance", params: { sort: "name" }
      expect(row_cells(dns).second).to eq("Not evaluated No advisory data imported for Debian:13")
      expect(row_cells(old).first(1)).to eq([ "Not evaluated No config report yet" ])
      expect(row_cells(old)[1..5]).to eq(%w[0 1 0 0 0])
      expect(words(page.at_css("tr#compliance_host_#{old.id} th .reason-line"))).to eq(
        "Vulnerabilities not evaluated now (its package manager is not supported); the open findings are from an earlier evaluation"
      )
      expect(strip("vuln_totals")["High"]).to eq(1)
    end

    it "explains a host with every check not readable or not applicable apart from one with no report" do
      Host.transaction { CisResult.where(host_id: backup.id).update_all(result: "not_applicable") }
      get "/compliance"
      expect(row_cells(backup).first).to eq("Not evaluated No check has a pass or fail result yet")
    end

    it "keeps filters and sort in the URL and composes them" do
      get "/compliance", params: { q: "a", tag: "lab", status: "attention", sort: "pass_rate", vuln: "critical" }
      expect(row_names).to eq([ "Web A" ])
      expect(page.at_css("input[name=q]")["value"]).to eq("a")
      expect(page.at_css("select[name=tag] option[selected]").text).to eq("lab")
      expect(page.at_css("select[name=status] option[selected]").text).to eq("Has open failures or findings")
      expect(page.at_css("select[name=sort] option[selected]").text).to eq("Lowest CIS pass rate")
      expect(page.at_css("input[name=vuln]")["value"]).to eq("critical")
      expect(page.at_css("th[aria-sort=ascending]").text).to eq("CIS pass rate")
      expect(page.at_css("#vuln_totals a[aria-current=true] .sev").text).to eq("Critical")
      expect(words(page.at_css("#severity_filter"))).to eq("Showing hosts with open critical vulnerability findings. Show every host")
      expect(Rack::Utils.parse_query(URI(page.at_css("#severity_filter a")["href"]).query)).to eq("q" => "a", "tag" => "lab", "status" => "attention", "sort" => "pass_rate")
      host_link = page.at_css("th a[href*='sort=name']")["href"]
      expect(Rack::Utils.parse_query(URI(host_link).query)).to eq("q" => "a", "tag" => "lab", "status" => "attention", "vuln" => "critical", "sort" => "name")
      expect(page.css("select[name=status] option").map(&:text)).to eq([ "All hosts", "Has open failures or findings", "Has critical or high", "No open findings", "Not evaluated" ])
      expect(page.css("select[name=tag] option").map(&:text)).to eq([ "All tags", "ci", "infra", "lab", "storage", "web" ])

      get "/compliance", params: { cis: "high", sort: "name" }
      expect(row_names).to eq([ "Build runner" ])
      expect(page.at_css("input[name=cis]")["value"]).to eq("high")
      expect(words(page.at_css("#severity_filter"))).to start_with("Showing hosts with open high CIS-aligned check failures.")

      get "/compliance", params: { cis: "high", vuln: "critical" } # both apply, and both are said (review of #128)
      expect(row_names).to eq([])
      get "/compliance", params: { cis: "medium", vuln: "critical" }
      expect(row_names).to eq([ "Web A" ])
      expect(words(page.at_css("#severity_filter"))).to eq(
        "Showing hosts with open medium CIS-aligned check failures and open critical vulnerability findings. Show every host"
      )

      get "/compliance", params: { status: "not_evaluated", sort: "name" }
      expect(row_names).to eq([ "Build runner", "DNS resolver" ])
      expect(words(page.at_css("#compliance_pager"))).to eq("2 of 4 active hosts.")
    end

    it "filters by distribution from the URL, as the Data sources page links to it" do
      record_inventory(web)
      get "/compliance", params: { ecosystem: "Debian:13", sort: "name" }
      expect(row_names).to eq([ "Build runner", "Web A" ])
      expect(page.at_css("input[name=ecosystem]")["value"]).to eq("Debian:13")
      expect(words(page.at_css("#ecosystem_filter"))).to eq("Showing hosts running Debian:13. Show every distribution")
      expect(query(page.at_css("#ecosystem_filter a"))).to eq("sort" => "name")
      expect(query(page.at_css("th a[href*='sort=pass_rate']"))).to eq("ecosystem" => "Debian:13", "sort" => "pass_rate")
      get "/compliance", params: { ecosystem: "Debian:13", tag: "storage" }
      expect(words(page.at_css("#no_matches strong"))).to eq(%(No hosts match tag "storage" with distribution Debian:13.))
    end

    it "explains when nothing matches, with a way back" do
      get "/compliance", params: { tag: "storage", status: "not_evaluated", cis: "low" }
      expect(words(page.at_css("#no_matches strong"))).to eq(%(No hosts match tag "storage", status "Not evaluated", and open low CIS-aligned check failures.))
      expect(page.at_css("#no_matches a")["href"]).to eq("/compliance")
      get "/compliance", params: { q: "zzz", vuln: "unknown" }
      expect(words(page.at_css("#no_matches strong"))).to eq(%(No hosts match "zzz" with open unknown vulnerability findings.))
    end

    it "pages a large fleet" do
      stub_const("FleetCompliance::PER_PAGE", 3)
      get "/compliance", params: { sort: "name" }
      expect(row_names).to eq([ "Backup target", "Build runner", "DNS resolver" ])
      expect(words(page.at_css("#compliance_pager"))).to eq("Hosts 1–3 of 4 Previous · Page 1 of 2 · Next")
      expect(query(page.at_css("#compliance_pager a[rel=next]"))).to eq("sort" => "name", "page" => "2")
      get "/compliance", params: { sort: "name", page: 2, tag: "lab" }
      expect(words(page.at_css("#compliance_pager"))).to eq("1 of 4 active hosts.")
      get "/compliance", params: { sort: "name", page: 2 }
      expect(row_names).to eq([ "Web A" ])
      expect(words(page.at_css("#compliance_pager"))).to eq("Hosts 4–4 of 4 Previous · Page 2 of 2 · Next")
      expect(query(page.at_css("#compliance_pager a[rel=prev]"))).to eq("sort" => "name")
      stub_const("FleetCompliance::PER_PAGE", 1)
      get "/compliance", params: { page: 3, status: "attention" }
      expect(words(page.at_css("#compliance_pager"))).to eq("Hosts 2–2 of 2 matching Previous · Page 2 of 2 · Next")
      get "/compliance", params: { page: 3, sort: "name" }
      expect(query(page.at_css("#compliance_pager a[rel=prev]"))).to eq("sort" => "name", "page" => "2")
    end

    it "says CIS-aligned and passes N of M checks, never compliant" do
      get "/compliance"
      text = words(page.at_css("main"))
      expect(text).to include("CIS-aligned", "passes 7 of 12 checks")
      expect(text).not_to match(/CIS[- ]compliant|\bcompliant\b|compliance level/i)
      get "/"
      expect(words(page.at_css("main"))).not_to match(/\bcompliant\b/i)
    end

    it "opts into morphing page refreshes on the fleet stream, as the fleet list does" do
      get "/compliance"
      expect(page.at_css('meta[name="turbo-refresh-method"]')["content"]).to eq("morph")
      expect(page.at_css("turbo-cable-stream-source")["id"]).to eq("fleet_stream")
    end
  end

  context "before anything is evaluated" do
    let!(:host) { enrolled_host(name: "DNS resolver").first }

    it "says no rules are defined, and never draws zeros for counts it does not have" do
      get "/compliance"
      expect(cell_words(page.at_css("#no_rules"))).to eq("No rules are defined. CIS pass rates and failure counts are blank until rules are imported. Open vulnerability findings are not affected.")
      expect(page.css(".sevstrip")).to be_empty
      expect(cell_words(page.at_css("#cis_totals p.sheet"))).to start_with("Not evaluated No active host has a pass, fail, or not readable result")
      expect(cell_words(page.at_css("#vuln_totals p.sheet"))).to start_with("Not evaluated No active host is evaluated for vulnerabilities now")
      expect(row_cells(host)).to eq([ "Not evaluated No rules are defined", "Not evaluated No inventory yet, so the distribution is not known", "Never" ])
      expect(words(page.at_css("#cis_totals .muted"))).to eq("0 of 1 host evaluated. Not evaluated hosts are not counted.")
    end

    it "says what is missing when every check is not applicable and every host's last matching could not evaluate it (review of #128)" do
      rules = compliance_rules(1).values.flatten
      cis_results!(host, rules.to_h { |r| [ r, "not_applicable" ] })
      host_config!(host)
      vulns_evaluated!(host, state: "not_evaluated", reason: "unreadable_packages")
      get "/compliance"
      expect(cell_words(page.at_css("#cis_totals p.sheet"))).to eq(
        "Not evaluated No active host has a pass, fail, or not readable result, so there is no failure to count. This is not zero failures."
      )
      expect(cell_words(page.at_css("#vuln_totals p.sheet"))).to eq(
        "Not evaluated No active host is evaluated for vulnerabilities now; each host's reason is in the table. This is not zero findings."
      )
    end

    it "says when matching has not run yet" do
      record_inventory(host)
      package_set!(host)
      import_advisories(osv_record) # advisory data for Debian:13, before the match job has run
      get "/compliance"
      expect(row_cells(host).second).to eq("Not evaluated Not matched against advisories yet")
    end
  end

  # P2-S12: 50 hosts, 40 rules each (2,000 results), and about 250 open findings, in under 2 seconds and a fixed number
  # of queries whatever the fleet size. Measured about 80 ms and 13 queries on a laptop (SHOW_TIMINGS=1 prints it).
  it "renders 50 hosts in under 2 seconds, in a fixed number of queries whatever the fleet size" do
    rules = compliance_rules(10).values.flatten
    results = %w[pass pass pass pass pass pass pass fail not_readable not_applicable]
    build = lambda do |count, offset|
      Array.new(count) do |i|
        host = enrolled_host(tags: [ "t#{i % 7}", "lab" ]).first
        record_heartbeat(host)
        cis_results!(host, rules.each_with_index.to_h { |r, j| [ r, results[(i + j + offset) % results.size] ] })
        host_config!(host)
        package_set!(host)
        if (i % 10).zero?
          record_inventory(host) # matching has not run: HostContext gives the reason
        else
          vulns_evaluated!(host)
          findings!(host, *Advisory::SEVERITIES.cycle.first(i % 13))
        end
        host
      end
    end
    build.(3, 0)
    get "/compliance" # warm up
    few = count_queries { get "/compliance" }
    build.(47, 3)
    many = count_queries { get "/compliance" }
    expect(many).to eq(few)
    expect(many).to be <= 15
    timings = Array.new(3) { Benchmark.realtime { get "/compliance" } }
    expect(row_names.size).to eq(50)
    expect(timings.min).to be < 2.0
    fleet = Array.new(3) { Benchmark.realtime { get "/" } }
    expect(fleet.min).to be < 2.0
    fleet_queries = count_queries { get "/" }
    puts format("\n  50 hosts, 2,000 CIS results, %d open findings: /compliance %.0f ms (best of 3), %d queries; / %.0f ms, %d queries",
                VulnerabilityFinding.active.count, timings.min * 1000, many, fleet.min * 1000, fleet_queries) if ENV["SHOW_TIMINGS"]
  end
end
