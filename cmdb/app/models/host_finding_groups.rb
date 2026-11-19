# One page of a host's vulnerability findings grouped by binary package and architecture, biggest offenders first
# (P2-D04, FR-2.4; the owner's request to make the Vulnerabilities tab actionable). The tab shows one row per package
# with its findings collapsed under it.
#
# - Rank: the package with the most critical findings first, then the most high, medium, low, and unknown ones (a
#   severity vector compared in that order, so one critical outranks any number of high), then the most with a fix
#   available, then the package name and architecture (bytewise, "C" collation). Counts are of the findings shown, so
#   the severity, text, and triage filters rank what they keep.
# - Fixable: the finding's fixed version is known, that is, the advisory's affected range for the host's release
#   (its ecosystem, such as Debian:13) that the installed version is in has a "fixed" event. Nothing in the data says
#   whether that version is already in the host's repositories, so it is not checked.
# - Pages: keyset pages of PER_PAGE packages after (or before) a package, "name:architecture". The groups are
#   aggregated and ranked in the database in one query whatever the page (a host has at most a few thousand findings);
#   only the page's packages' findings are loaded, in one more query. A cursor naming a package no longer listed reads
#   the first page.
class HostFindingGroups
  PER_PAGE = 50
  CURSOR_MAX = 161 # a package name (128), ":", and an architecture (32)

  # One package's row: its findings in display order and its counts per severity.
  Group = Data.define(:package, :architecture, :counts, :fixable, :findings) do
    def total = counts.values.sum
    def worst = Advisory::SEVERITIES.find { |severity| counts.fetch(severity, 0).positive? }
    def installed_version = findings.first.installed_version
    def first_seen_at = findings.map(&:first_seen_at).min
    def key = "#{package}:#{architecture}"
    def states = findings.map(&:state).tally
  end

  attr_reader :groups, :previous, :next, :package_count, :severity_counts

  # The cursor named by a parameter, or nil: "name:architecture", split at the last colon.
  def self.cursor(value)
    value = value.to_s
    return nil if value.empty? || value.length > CURSOR_MAX

    package, _, architecture = value.rpartition(":")
    [ package, architecture ] unless package.empty? || architecture.empty?
  end

  # scope: the findings shown, a VulnerabilityFinding.with_details relation joined to advisories. after, before:
  # cursors from HostFindingGroups.cursor (before wins).
  def initialize(scope, after: nil, before: nil, per_page: PER_PAGE)
    @scope = scope
    @per_page = per_page
    load(before ? [ before, true ] : [ after, false ])
  end

  def finding_count = severity_counts.values.sum
  def paged? = previous || self.next

  private

  # The rank's order: every key ascending (counts negated), so a page boundary is one rank comparison.
  ORDER = '-g.critical, -g.high, -g.medium, -g.low, -g.unknown, -g.fixable, g.package COLLATE "C", g.architecture COLLATE "C"'.freeze
  # The totals over every group, beside each row.
  TOTALS = "count(*) OVER () AS packages, sum(g.critical) OVER () AS total_critical, sum(g.high) OVER () AS total_high, " \
           "sum(g.medium) OVER () AS total_medium, sum(g.low) OVER () AS total_low, sum(g.unknown) OVER () AS total_unknown".freeze

  def load((cursor, backwards))
    rows = read(cursor, backwards)
    # A cursor naming a package no longer listed, or past the end, and Previous to the first page: the first page.
    return load([ nil, false ]) if cursor && (rows.empty? || (backwards && rows.size <= @per_page))

    totals = rows.first || {}
    @package_count = totals.fetch("packages", 0)
    @severity_counts = Advisory::SEVERITIES.to_h { |severity| [ severity, totals["total_#{severity}"].to_i ] }.select { |_, count| count.positive? }
    page = rows.first(@per_page)
    page.reverse! if backwards
    @previous = cursor ? page.first.values_at("package", "architecture") : nil
    @next = backwards || rows.size > @per_page ? page.last.values_at("package", "architecture") : nil
    @groups = build(page)
  end

  # The page's groups (with one more, to tell whether there is a next page) after or before the cursor's, each with
  # its rank and the totals over every group, in one query: the groups are aggregated once (a CTE), ranked with a
  # window, and read past the cursor's rank.
  def read(cursor, backwards)
    aggregated = @scope.except(:order, :preload, :includes).reselect(*aggregates).group("vulnerability_findings.package", "vulnerability_findings.architecture")
    ranked = VulnerabilityFinding.unscoped.from("g").select(Arel.sql("g.*"), Arel.sql("row_number() OVER (ORDER BY #{ORDER}) AS rank"), Arel.sql(TOTALS))
    query = VulnerabilityFinding.unscoped.with(g: aggregated, r: ranked).from("r").select("r.*")
    if cursor
      query = query.where("r.rank #{backwards ? '<' : '>'} (SELECT c.rank FROM r c WHERE c.package = ? AND c.architecture = ?)", *cursor)
    end
    query = query.order(backwards ? Arel.sql("r.rank DESC") : Arel.sql("r.rank")).limit(@per_page + 1)
    VulnerabilityFinding.connection.select_all(query.arel, "HostFindingGroups").to_a
  end

  def aggregates
    Advisory::SEVERITIES.map { |severity| Arel.sql(VulnerabilityFinding.sanitize_sql([ "count(*) FILTER (WHERE advisories.severity = ?) AS #{severity}", severity ])) } +
      [ Arel.sql("count(*) FILTER (WHERE vulnerability_findings.fixed_version IS NOT NULL) AS fixable"),
        Arel.sql("vulnerability_findings.package"), Arel.sql("vulnerability_findings.architecture") ]
  end

  # The page's groups with their findings, loaded in one query and sorted worst first, then the earliest first seen.
  def build(rows)
    return [] if rows.empty?

    keys = rows.map { |row| row.values_at("package", "architecture") }
    findings = @scope.where(package: keys.map(&:first).uniq, architecture: keys.map(&:last).uniq).to_a
                     .group_by { |finding| [ finding.package, finding.architecture ] }
    rows.map do |row|
      Group.new(package: row["package"], architecture: row["architecture"], fixable: row["fixable"],
                counts: Advisory::SEVERITIES.to_h { |severity| [ severity, row[severity] ] },
                findings: findings.fetch([ row["package"], row["architecture"] ]).sort_by { |f| [ Advisory::SEVERITIES.index(f.advisory.severity), f.first_seen_at, f.advisory.advisory_id ] })
    end
  end
end
