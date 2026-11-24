require "rails_helper"

# A package row loads at most HostFindingGroups.load_max findings (#318): the NESTED_MAX the tab draws and one more, the
# first in the order the row draws them. A row with more counts itself from its aggregated group, so its total,
# severities, fixes, states, resolutions, and first seen are those of every finding, as when they were all loaded.
# Fix available's rows load witnesses too, for "Upgrade to". Package names and versions are a Debian 13 host's;
# advisory ids are made up.
RSpec.describe HostFindingGroups do
  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later)
    allow(CisEvaluationJob).to receive(:perform_later)
    stub_const("HostTriageSections::NESTED_MAX", 2)
  end

  let(:host) { debian_host(name: "vm-01.example.lan", packages: [ [ "bash", "5.2.37-2", "bash" ], [ "curl", "8.14.1-2", "curl" ] ]) }
  let(:severities) { %w[critical high medium critical high low unknown] }

  def cvss(impact) = [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/#{impact}" } ]
  def id(i) = "DEBIAN-CVE-2026-95#{format('%03d', i)}"

  # Seven bash advisories of these severities (unknown has no score), fixed at 5.2.37-(3 + i % 3) but for the last
  # two (low and unknown, drawn last), which have no fix; one curl advisory.
  def import
    scores = { "critical" => [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" } ],
               "high" => cvss("C:H/I:H/A:H"), "medium" => cvss("C:H/I:N/A:N"), "low" => cvss("C:L/I:N/A:N"), "unknown" => nil }
    records = severities.each_with_index.map { |severity, i| osv_record(id: id(i), package: "bash", fixed: i < 5 ? "5.2.37-#{3 + (i % 3)}" : nil, severity: scores.fetch(severity)) }
    import_advisories(*records, osv_record(id: "DEBIAN-CVE-2026-96001", package: "curl", fixed: nil), full: true)
    VulnerabilityMatcher.match!([ host.id ])
    expect(VulnerabilityFinding.joins(:advisory).where(host:, package: "bash").order("advisories.advisory_id").pluck("advisories.severity")).to eq(severities)
  end

  def bash(*indexes) = VulnerabilityFinding.joins(:advisory).where(host:, package: "bash", advisories: { advisory_id: indexes.map { |i| id(i) } })

  def scope = VulnerabilityFinding.where(host_id: host.id).joins(:advisory)

  # The findings each statement loads.
  def loading
    loaded = []
    callback = ->(*, payload) { loaded << payload[:record_count] if payload[:class_name] == "VulnerabilityFinding" }
    result = ActiveSupport::Notifications.subscribed(callback, "instantiation.active_record") { yield }
    [ result, loaded ]
  end

  # A row's counts over every finding of the package, read from the table.
  def expected(findings)
    { total: findings.size, counts: Advisory::SEVERITIES.to_h { |severity| [ severity, findings.count { |f| f.advisory.severity == severity } ] },
      fixable: findings.count(&:fixable), first_seen_at: findings.map(&:first_seen_at).min, states: findings.map(&:state).tally,
      resolutions: findings.filter_map(&:resolution).tally }
  end

  def counts(group) = { total: group.total, counts: group.counts, fixable: group.fixable, first_seen_at: group.first_seen_at, states: group.states, resolutions: group.resolutions }

  # The order a row draws its findings in.
  def ordered(findings) = findings.sort_by { |f| [ Advisory::SEVERITIES.index(f.advisory.severity), f.first_seen_at, f.advisory.advisory_id ] }

  it "loads at most load_max findings a row, the first it draws, and counts a row with more from its group" do
    import
    # Mixed states and resolutions, a resolved finding that kept its fixed version (no fix of an active finding), and
    # the earliest first seen on a finding drawn last, so none of the counts can be read from the findings loaded.
    bash(3).update_all(state: "reopened", reopened_at: Time.current)
    bash(1).update_all(state: "resolved", resolution: "fixed", resolved_at: Time.current, bucket: nil, bucket_rule: nil, kev: nil)
    bash(2).update_all(state: "resolved", resolution: "removed", resolved_at: Time.current, bucket: nil, bucket_rule: nil, kev: nil)
    bash(6).update_all(first_seen_at: 3.days.ago)
    # First seen before the advisory id within a severity: 3 before 0 (critical), and 4 before 1 (high), so the third
    # finding loaded is 4.
    bash(3, 4).update_all(first_seen_at: 2.days.ago)
    all = VulnerabilityFinding.where(host:, package: "bash").preload(:advisory).to_a
    expect(HostFindingGroups.load_max).to eq(3)

    groups, loaded = loading { described_class.new(scope, host_id: host.id, rank: :severity) }
    expect(loaded.sum).to eq(3 + 1) # bash's first three, and curl's one
    group = groups.groups.find { |g| g.package == "bash" }
    expect(group.findings.map(&:id)).to eq(ordered(all).first(3).map(&:id))
    expect(group.findings.map { |f| f.advisory.advisory_id }).to eq([ id(3), id(0), id(4) ])
    expect(group.witnesses).to be_empty
    expect(counts(group)).to eq(expected(all))
    expect(group.states).to eq("open" => 4, "reopened" => 1, "resolved" => 2)
    expect(group.resolutions).to eq("fixed" => 1, "removed" => 1)
    # 0, 3, and 4 are active with a fix; 1 and 2 resolved with their fixed versions kept, which are no fix.
    expect(group.fixable).to eq(3)
    expect(group.first_seen_at).to eq(all.find { |f| f.advisory.advisory_id == id(6) }.first_seen_at)

    # A row with no more than load_max counts the findings it loaded, as before.
    curl = groups.groups.find { |g| g.package == "curl" }
    expect(counts(curl)).to eq(expected(VulnerabilityFinding.where(host:, package: "curl").preload(:advisory).to_a))

    # The resolved list's rows alike.
    resolved = described_class.new(scope.where(state: "resolved"), host_id: host.id, rank: :severity).groups.sole
    expect(counts(resolved)).to eq(expected(all.select { |f| f.state == "resolved" }))
  end

  it "loads a Fix available row's witnesses past load_max: one finding of each fixed version, and every one with none" do
    import
    open = scope.where(state: %w[open reopened])
    plain, = loading { described_class.new(open, host_id: host.id) }
    expect(plain.groups.find { |g| g.package == "bash" }.witnesses).to be_empty

    groups, loaded = loading { described_class.new(open, host_id: host.id, witnesses: true) }
    group = groups.groups.find { |g| g.package == "bash" }
    all = VulnerabilityFinding.where(host:, package: "bash").preload(:advisory).to_a
    expect(group.findings.map(&:id)).to eq(ordered(all).first(3).map(&:id))
    # Each fixed version at most once (its first finding by id, when that one is not among the first three), and both
    # findings with no fix: together with the first three, every fixed version of the row.
    versions = group.witnesses.filter_map(&:last_fixed_version)
    expect(versions).to eq(versions.uniq)
    expect(group.witnesses.count { |f| f.last_fixed_version.nil? }).to eq(2)
    expect(group.loaded.filter_map(&:last_fixed_version).uniq).to match_array(all.filter_map(&:last_fixed_version).uniq)
    expect(loaded.sum).to eq(1 + group.loaded.size)
    expect(group.loaded.size).to be < all.size
    expect(counts(group)).to eq(expected(all))
  end

  it "keeps the statements' count and pins the limit in SQL" do
    import
    sql = []
    callback = ->(*, payload) { sql << payload[:sql] unless payload[:name] == "SCHEMA" }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { described_class.new(scope, host_id: host.id, rank: :severity) }
    statements = sql.reject { |s| s.include?("FROM \"advisories\"") } # the preload
    expect(statements.size).to eq(2)
    expect(statements.last).to include("row_number() OVER (PARTITION BY vulnerability_findings.package, vulnerability_findings.architecture ORDER BY")
                           .and match(/row_rank <= (3|\$\d+)/)
  end
end
