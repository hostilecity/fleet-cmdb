require "rails_helper"

# The fleet compliance query (P2-D05, FR-2.5): per-host and fleet-wide counts aggregated in the database, checked against
# the same rows counted again in Ruby, and the filters and sorts of the approved mockup (owner decision Q9).
RSpec.describe FleetCompliance do
  def names(params = {}) = described_class.new(params).rows.map { |row| row.host.name }

  def row(host) = described_class.new.rows.find { |r| r.host.id == host.id }

  let!(:rules) { compliance_rules(3) }
  let(:rule) { ->(key) { rules.values.flatten.find { |r| r.key == key } } }
  let(:all_rules) { rules.values.flatten }

  # Every rule passes except the ones named.
  def results(host, **named)
    by_key = named.flat_map { |result, keys| Array(keys).map { |key| [ key.to_s, result.to_s ] } }.to_h
    cis_results!(host, all_rules.to_h { |r| [ r, by_key.fetch(r.key, "pass") ] })
  end

  let!(:build) { enrolled_host(name: "Build runner", tags: %w[ci]).first }
  let!(:web) { enrolled_host(name: "Web A", tags: %w[web lab]).first }
  let!(:media) { enrolled_host(name: "Media server", tags: %w[media]).first }
  let!(:backup) { enrolled_host(name: "Backup target", tags: %w[storage]).first }
  let!(:dns) { enrolled_host(name: "DNS resolver", tags: %w[infra]).first }
  let!(:old) { enrolled_host(name: "Old findings", tags: %w[lab]).first }
  let!(:pending) { create(:host, name: "Lab sandbox", tags: %w[lab]) }
  let!(:revoked) { create(:host, :revoked, name: "Old proxy", tags: %w[web]) }
  let!(:retired) { create(:host, :retired, name: "Gone", tags: %w[lab]) }

  before do
    results(build, fail: %w[critical-0 high-0 medium-0 low-0], not_readable: %w[medium-1])
    host_config!(build)
    record_inventory(build) # inventoried, but no package report: matching has not run

    results(web, fail: %w[medium-0 low-0], not_applicable: %w[low-1])
    host_config!(web)
    package_set!(web)
    vulns_evaluated!(web)
    findings!(web, "critical", "low")

    results(media, fail: %w[high-0 high-1 medium-0 medium-1 low-0])
    host_config!(media)
    package_set!(media)
    vulns_evaluated!(media)
    findings!(media, "high", "medium", "low", "unknown")
    findings!(media, "medium", state: "reopened")
    findings!(media, "critical", state: "resolved")

    results(backup)
    host_config!(backup)
    package_set!(backup)
    vulns_evaluated!(backup)
    findings!(backup, "high", state: "resolved")

    results(old)
    host_config!(old)
    vulns_evaluated!(old, state: "not_evaluated", reason: "unreadable_packages")
    findings!(old, "high") # from an earlier evaluation

    [ revoked, retired, pending ].each do |host|
      results(host, fail: %w[critical-0 critical-1])
      findings!(host, "critical")
    end

    # A disabled rule's results are not evaluated, and count nowhere.
    disabled, = define_cis_rules(cis_rule_hash(key: "disabled-0", severity: "critical"))
    CisRule.transaction { disabled.disable!(actor: Audit::SYSTEM) }
    cis_results!(backup, disabled => "not_evaluated")

    # Raising a rule's severity after it failed leaves the result on the version that produced it, as the host tab shows.
    CisRule.transaction { rule.("high-1").revise!(CisRules::Definition.from_h(cis_rule_hash(key: "high-1", severity: "critical", title: "High check 1")), actor: Audit::SYSTEM) }
  end

  it "counts each active host's open CIS failures and vulnerability findings by severity, as the rows say" do
    active = [ build, web, media, backup, dns, old ]
    expect(described_class.new.rows.map(&:host)).to match_array(active)
    compliance = CisCompliance.for_hosts(active.map(&:id))
    active.each do |host|
      r = row(host)
      expect(r.cis).to eq(expected_cis(host)), host.name
      expect(r.vulns).to eq(expected_vulns(host)), host.name
      expect(r.pass_rate).to eq(compliance.fetch(host.id).pass_rate), host.name
      expect(r.cis_counted).to eq(compliance.fetch(host.id).counted), host.name
    end
    expect(row(media).cis).to eq("critical" => 0, "high" => 2, "medium" => 2, "low" => 1)
    expect(row(media).vulns).to eq("critical" => 0, "high" => 1, "medium" => 2, "low" => 1, "unknown" => 1)
    expect(row(build).pass_rate).to eq(7.fdiv(12))
  end

  it "counts the whole fleet as the sum of its active hosts, whatever the filters" do
    totals = described_class.totals
    active = [ build, web, media, backup, dns, old ]
    expect(totals.hosts).to eq(6)
    expect(totals.cis).to eq(FleetCompliance::CIS_SEVERITIES.index_with { |s| active.sum { |h| expected_cis(h)[s] } })
    expect(totals.cis).to eq("critical" => 1, "high" => 3, "medium" => 4, "low" => 3)
    expect(totals.vulns).to eq(Advisory::SEVERITIES.index_with { |s| active.sum { |h| expected_vulns(h)[s] } })
    expect(totals.vulns).to eq("critical" => 1, "high" => 2, "medium" => 2, "low" => 2, "unknown" => 1)
    summaries = CisCompliance.for_hosts(active.map(&:id)).values
    expect([ totals.cis_passed, totals.cis_counted ]).to eq([ summaries.sum(&:passed), summaries.sum(&:counted) ])
    expect(totals.pass_rate).to eq(summaries.sum(&:passed).fdiv(summaries.sum(&:counted)))
    expect([ totals.cis_evaluated, totals.vulns_evaluated, totals.vulns_not_evaluated ]).to eq([ 5, 3, 3 ])
    expect(totals.cis_failed).to eq(11)
    expect(totals.vulns_open).to eq(8)
  end

  it "tells not evaluated apart from nothing open" do
    expect(row(dns)).to have_attributes(cis_evaluated?: false, pass_rate: nil, vulns_shown?: false, nothing_evaluated?: true, vuln_reason: "no_inventory", config_report?: false)
    expect(row(build)).to have_attributes(cis_evaluated?: true, vulns_evaluated?: false, vulns_shown?: false, vuln_reason: "no_package_report", nothing_evaluated?: false)
    expect(row(backup)).to have_attributes(cis_evaluated?: true, cis_failed: 0, vulns_evaluated?: true, vulns_open: 0, nothing_evaluated?: false)
    expect(row(old)).to have_attributes(vulns_evaluated?: false, vulns_shown?: true, vulns_open: 1, vuln_reason: "unreadable_packages", vuln_ecosystem: "Debian:13")
  end

  it "sorts worst first, with hosts that have nothing evaluated last (Q9)" do
    expect(names).to eq([ "Build runner", "Web A", "Media server", "Old findings", "Backup target", "DNS resolver" ])
  end

  it "sorts by lowest pass rate and by most open vulnerabilities, not evaluated hosts last, then by name" do
    expect(names(sort: "pass_rate")).to eq([ "Build runner", "Media server", "Web A", "Backup target", "Old findings", "DNS resolver" ])
    expect(names(sort: "vulns")).to eq([ "Media server", "Web A", "Old findings", "Backup target", "Build runner", "DNS resolver" ])
    expect(names(sort: "name")).to eq([ "Backup target", "Build runner", "DNS resolver", "Media server", "Old findings", "Web A" ])
    expect(names(sort: "bogus")).to eq(names)
  end

  it "breaks a tie in open vulnerabilities by name, not by severity, which is worst first's job (review of #128)" do
    zulu, alpha = [ "Tie Zulu", "Tie Alpha" ].map { |name| enrolled_host(name:).first.tap { |h| vulns_evaluated!(h) } }
    findings!(zulu, "critical", "critical")
    findings!(alpha, "low", "low")
    expect(names(sort: "vulns", q: "Tie ")).to eq([ "Tie Alpha", "Tie Zulu" ])
    expect(names(q: "Tie ")).to eq([ "Tie Zulu", "Tie Alpha" ])
  end

  it "filters by status, severity, tag, and search, and composes them" do
    expect(names(status: "attention", sort: "name")).to eq([ "Build runner", "Media server", "Old findings", "Web A" ])
    expect(names(status: "critical_high", sort: "name")).to eq([ "Build runner", "Media server", "Old findings", "Web A" ])
    expect(names(status: "clean")).to eq([ "Backup target" ])
    expect(names(status: "not_evaluated", sort: "name")).to eq([ "Build runner", "DNS resolver", "Old findings" ])
    expect(names(cis: "high", sort: "name")).to eq([ "Build runner", "Media server" ])
    expect(names(vuln: "high", sort: "name")).to eq([ "Media server", "Old findings" ])
    expect(names(vuln: "unknown")).to eq([ "Media server" ])
    expect(names(tag: "LAB", sort: "name")).to eq([ "Old findings", "Web A" ])
    expect(names(q: "MEDIA")).to eq([ "Media server" ])
    expect(names(tag: "lab", status: "not_evaluated")).to eq([ "Old findings" ])
    expect(names(status: "bogus", cis: "bogus", vuln: "bogus").size).to eq(6)
  end

  it "filters by the distribution release an ecosystem covers, from the inventory, for the Data sources page's link" do
    record_inventory(media)
    record_inventory(web, os: { "id" => "alpine", "version_id" => "3.20", "pretty_name" => "Alpine Linux v3.20" })
    expect(names(ecosystem: "Debian:13", sort: "name")).to eq([ "Build runner", "Media server" ])
    expect(names(ecosystem: "Debian:12").size).to eq(6) # not in the fleet profile: ignored
    expect(described_class.new(ecosystem: "Debian:13").params_with).to eq(ecosystem: "Debian:13")
  end

  it "lists the tags of active hosts only" do
    expect(described_class.tags).to eq(%w[ci infra lab media storage web])
  end

  it "keeps the filters in link parameters, leaving defaults out" do
    list = described_class.new(q: "a", tag: "lab", status: "clean", cis: "low", sort: "worst", page: "2")
    expect(list.params_with(sort: "name")).to eq(q: "a", tag: "lab", status: "clean", cis: "low", sort: "name")
    expect(list.params_with(cis: nil)).to eq(q: "a", tag: "lab", status: "clean")
    expect(list).to be_filtered
    expect(described_class.new).not_to be_filtered
    expect([ list.aria_sort("worst"), list.aria_sort("name") ]).to eq(%w[ascending none])
  end

  it "pages by 100" do
    stub_const("FleetCompliance::PER_PAGE", 4)
    second = described_class.new(page: "2", sort: "name")
    expect([ second.total, second.pages, second.page, second.first_row, second.last_row ]).to eq([ 6, 2, 2, 5, 6 ])
    expect(second.rows.map { |r| r.host.name }).to eq([ "Old findings", "Web A" ])
    expect(described_class.new(page: "99").page).to eq(2)
    expect(described_class.new(q: "no such host")).to have_attributes(total: 0, pages: 1, first_row: 0, last_row: 0)
  end

  it "writes one count column for each severity a rule version or an advisory can have" do
    allowed = CisRuleVersion.connection.select_value("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'cis_rule_versions_severity'")
    expect(FleetCompliance::CIS_SEVERITIES).to match_array(allowed.scan(/'(\w+)'/).flatten.uniq)
    expect(FleetCompliance::JOINS.scan(/AS cis_(critical|high|medium|low)\b/).flatten).to eq(FleetCompliance::CIS_SEVERITIES)
    expect(FleetCompliance::JOINS.scan(/AS vuln_(\w+)/).flatten).to eq(Advisory::SEVERITIES)
  end

  it "builds a page in a fixed number of queries" do
    list = described_class.new(sort: "worst")
    queries = count_queries { list.rows && list.total && described_class.totals && described_class.tags }
    expect(queries).to be <= 8 # rows, HostContext (three), count, totals, tags
  end
end
