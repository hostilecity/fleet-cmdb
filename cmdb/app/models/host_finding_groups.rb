# One page of a host's vulnerability findings grouped by binary package and architecture (P2-D04, FR-2.4; the owner's
# request to make the Vulnerabilities tab actionable). The tab shows one row per package with its findings collapsed
# under it.
#
# - Order. The open and reopened list (rank: :offenders) puts the biggest offenders first: the most critical findings,
#   then the most high, medium, low, and unknown ones (a severity vector compared in that order, so one critical
#   outranks any number of high), then the most with a fix available, then the package name and architecture
#   (bytewise, "C" collation). The resolved list (rank: :severity) keeps the tab's earlier order, worst severity then
#   the earliest first seen, since a resolved finding is not something to act on (review of #253, S3). Counts are of
#   the findings shown, so the severity, text, and triage filters rank what they keep.
# - Fixable: the finding's stored fix (VulnerabilityFinding#fixable, VT-FIXABLE #256): its fixed version is
#   known, that is, the advisory's affected range for the host's release (its ecosystem, such as Debian:13) that the
#   installed version is in has a "fixed" event. Nothing in the data says whether that version is already in the
#   host's repositories, so it is not checked. The summaries count the same flag, so the fleet pages agree.
# - Pages: keyset pages of PER_PAGE packages after (or before) a cursor that holds the whole sort key of a row (its
#   counts, or its worst severity and first seen, then its package and architecture), so a page keeps its place when
#   the counts change under a live refresh (review of #253, S1): it shows the packages that now sort after that key.
#   A cursor that does not parse, or one with nothing after (or before) it any more, reads the first page and says so
#   (notice). The groups are aggregated in the database in one query whatever the page (a host has at most a few
#   thousand findings), on the plain findings table; only the page's packages' findings are loaded, with their details
#   (VulnerabilityFinding.with_details_of: looked up for those findings only, #302), in one more query. A package whose findings
#   left the list between the two (a matching run committing, or a replica replaying) is left off the page rather
#   than failing it, and the page's rows count the findings loaded (S2).
class HostFindingGroups
  PER_PAGE = 50
  CURSOR_MAX = 300
  NAME = /\A[^,\s[:cntrl:]]{1,128}\z/

  # One package's row: its findings in display order and its counts per severity.
  Group = Data.define(:package, :architecture, :counts, :fixable, :findings) do
    def total = findings.size
    def worst = Advisory::SEVERITIES.find { |severity| counts.fetch(severity, 0).positive? }
    def installed_version = findings.first.installed_version
    def first_seen_at = findings.map(&:first_seen_at).min
    def key = "#{package}:#{architecture}"
    def states = findings.map(&:state).tally
    def resolutions = findings.filter_map(&:resolution).tally
  end

  # The sort key of each rank, SQL over the aggregated groups (g), every part ascending, so a page boundary is one row
  # comparison; and the cursor's values in the same shape.
  KEYS = {
    offenders: '-g.critical, -g.high, -g.medium, -g.low, -g.unknown, -g.fixable, g.package COLLATE "C", g.architecture COLLATE "C"',
    severity: 'g.worst_rank, g.first_seen_at, g.package COLLATE "C", g.architecture COLLATE "C"'
  }.freeze
  CURSOR_KEYS = {
    offenders: '(-(?::bigint), -(?::bigint), -(?::bigint), -(?::bigint), -(?::bigint), -(?::bigint), ? COLLATE "C", ? COLLATE "C")',
    severity: '(?::integer, ?::timestamp, ? COLLATE "C", ? COLLATE "C")'
  }.freeze
  TOTALS = "count(*) OVER () AS packages, sum(g.critical) OVER () AS total_critical, sum(g.high) OVER () AS total_high, " \
           "sum(g.medium) OVER () AS total_medium, sum(g.low) OVER () AS total_low, sum(g.unknown) OVER () AS total_unknown".freeze

  attr_reader :rank, :groups, :previous, :next, :package_count, :severity_counts, :notice

  # The cursor named by a parameter for a rank: nil when there is none, :invalid when it does not parse, else its
  # values (the counts, or the worst severity's rank and the first seen time, then the package and architecture).
  def self.cursor(value, rank)
    value = value.to_s
    return nil if value.empty?
    return :invalid if value.length > CURSOR_MAX

    *keys, package, architecture = value.split(",", -1)
    return :invalid unless NAME.match?(package.to_s) && NAME.match?(architecture.to_s)

    values = rank == :offenders ? counts_key(keys) : severity_key(keys)
    values ? [ *values, package, architecture ] : :invalid
  end

  def self.counts_key(keys) = keys.size == 6 && keys.all?(/\A\d{1,9}\z/) ? keys.map(&:to_i) : nil

  def self.severity_key(keys)
    return nil unless keys.size == 2 && keys.first.match?(/\A[1-5]\z/)

    [ keys.first.to_i, Time.iso8601(keys.last).utc ]
  rescue ArgumentError
    nil
  end

  # scope: the findings shown, a relation of findings joined to advisories: the plain table, or with details when a
  # filter reads one (VulnerabilityFinding.with_host_details). after, before:
  # cursors from HostFindingGroups.cursor for this rank (before wins).
  def initialize(scope, rank: :offenders, after: nil, before: nil, per_page: PER_PAGE)
    @scope = scope
    @rank = rank
    @per_page = per_page
    cursor = before || after
    @notice = :invalid if cursor == :invalid
    cursor = nil if cursor == :invalid
    load(cursor, !before.nil? && !cursor.nil?)
  end

  def finding_count = severity_counts.values.sum
  def paged? = previous || self.next

  private

  def load(cursor, backwards)
    rows = read(cursor, backwards)
    if cursor && rows.empty?
      @notice = :moved # nothing after (or before) the cursor any more: the list changed since the link was drawn
      return load(nil, false)
    end
    return load(nil, false) if backwards && rows.size <= @per_page # Previous to the first page, full

    totals = rows.first || {}
    @package_count = totals.fetch("packages", 0)
    @severity_counts = Advisory::SEVERITIES.to_h { |severity| [ severity, totals["total_#{severity}"].to_i ] }.select { |_, count| count.positive? }
    page = rows.first(@per_page)
    page.reverse! if backwards
    @groups = build(page)
    @previous = cursor ? cursor_of(page.first) : nil
    @next = backwards || rows.size > @per_page ? cursor_of(page.last) : nil
  end

  # A row's cursor: its whole sort key, as the database computed it.
  def cursor_of(row)
    keys = rank == :offenders ? [ *Advisory::SEVERITIES.map { |severity| row[severity] }, row["fixable"] ] : [ row["worst_rank"], row["first_seen_at"].utc.iso8601(6) ]
    [ *keys, row["package"], row["architecture"] ].join(",")
  end

  # The page's groups (with one more, to tell whether there is a next page) after or before the cursor's key, each
  # with the totals over every group, in one query: the groups are aggregated once (a CTE), the totals taken over all
  # of them with a window, and the page read past the cursor's key by a row comparison.
  def read(cursor, backwards)
    aggregated = @scope.except(:order, :preload, :includes).reselect(*aggregates).group("vulnerability_findings.package", "vulnerability_findings.architecture")
    totalled = VulnerabilityFinding.unscoped.from("g").select(Arel.sql("g.*"), Arel.sql(TOTALS))
    query = VulnerabilityFinding.unscoped.with(g: aggregated, r: totalled).from("r g").select(Arel.sql("g.*"))
    query = query.where("(#{KEYS.fetch(rank)}) #{backwards ? '<' : '>'} #{CURSOR_KEYS.fetch(rank)}", *cursor) if cursor
    order = KEYS.fetch(rank).split(", ").map { |key| backwards ? Arel.sql(key).desc : Arel.sql(key) }
    VulnerabilityFinding.connection.select_all(query.order(*order).limit(@per_page + 1).arel, "HostFindingGroups").to_a
  end

  def aggregates
    Advisory::SEVERITIES.map { |severity| Arel.sql(VulnerabilityFinding.sanitize_sql([ "count(*) FILTER (WHERE advisories.severity = ?) AS #{severity}", severity ])) } +
      [ Arel.sql("count(*) FILTER (WHERE #{VulnerabilityFinding::FIX_SQL}) AS fixable"),
        Arel.sql("min(array_position(ARRAY['critical', 'high', 'medium', 'low', 'unknown']::varchar[], advisories.severity)) AS worst_rank"),
        Arel.sql("min(vulnerability_findings.first_seen_at) AS first_seen_at"),
        Arel.sql("vulnerability_findings.package"), Arel.sql("vulnerability_findings.architecture") ]
  end

  # The page's groups with their findings, loaded in one query (the page's package and architecture pairs, not their
  # cross product) and sorted worst first, then the earliest first seen. Counts are taken from the rows loaded, and a
  # package with none left is left off the page.
  def build(rows)
    return [] if rows.empty?

    table = VulnerabilityFinding.arel_table
    pairs = rows.map { |row| Arel::Nodes::Grouping.new([ Arel::Nodes.build_quoted(row["package"]), Arel::Nodes.build_quoted(row["architecture"]) ]) }
    page = @scope.where(Arel::Nodes::In.new(Arel::Nodes::Grouping.new([ table[:package], table[:architecture] ]), pairs))
    findings = VulnerabilityFinding.with_details_of(page).preload(:advisory).to_a.group_by { |finding| [ finding.package, finding.architecture ] }
    rows.filter_map do |row|
      list = findings[[ row["package"], row["architecture"] ]] or next

      Group.new(package: row["package"], architecture: row["architecture"], fixable: list.count(&:fixable),
                counts: Advisory::SEVERITIES.to_h { |severity| [ severity, list.count { |f| f.advisory.severity == severity } ] },
                findings: list.sort_by { |f| [ Advisory::SEVERITIES.index(f.advisory.severity), f.first_seen_at, f.advisory.advisory_id ] })
    end
  end
end
