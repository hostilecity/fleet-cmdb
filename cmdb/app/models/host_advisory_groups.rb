# One page of a host's Needs attention findings grouped by advisory (VT-HOST-TAB #260, VT-D04; approved mockup
# host-vulns.html): one row per advisory, its packages listed, since a decision (VT-OVERRIDES) is taken per advisory
# and one advisory often names several binary packages of one source.
#
# - Order: the advisory's severity, worst first (epic decision 22, Q12: severity first inside each bucket), then known
#   exploited first (the stored KEV flag of any of its findings), then its id (bytewise, "C" collation).
# - Pages: keyset pages of PER_PAGE advisories after (or before) a cursor holding the whole sort key, as
#   HostFindingGroups does (review of #253, S1): a cursor that does not parse, or one with nothing past it any more,
#   reads the first page and says so (notice). The advisories are aggregated in the database in one query whatever the
#   page, on the plain findings table, and only the page's findings are loaded, with their details (looked up for
#   those findings only, #302), in one more. An advisory whose findings left the list between the
#   two is left off the page.
class HostAdvisoryGroups
  PER_PAGE = 50
  CURSOR_MAX = 200
  ID = /\A[^,\s[:cntrl:]]{1,128}\z/

  # One advisory's row: its findings (one per binary package and architecture), in package order.
  Group = Data.define(:advisory, :findings) do
    def kev? = findings.any?(&:kev)
    def packages = findings.map { |finding| "#{finding.package}:#{finding.architecture}" }.uniq
  end

  KEY = 'g.severity_rank, -g.kev_rank, g.advisory_key COLLATE "C"'.freeze
  CURSOR_KEY = '(?::integer, -(?::integer), ? COLLATE "C")'.freeze

  attr_reader :groups, :previous, :next, :advisory_count, :finding_count, :notice

  # The cursor a parameter names: nil when none, :invalid when it does not parse, else [severity rank, kev rank, id].
  def self.cursor(value)
    value = value.to_s
    return nil if value.empty?
    return :invalid if value.length > CURSOR_MAX

    rank, kev, id = value.split(",", 3)
    return :invalid unless rank.to_s.match?(/\A[1-5]\z/) && kev.to_s.match?(/\A[01]\z/) && ID.match?(id.to_s)

    [ rank.to_i, kev.to_i, id ]
  end

  # scope: the findings shown, a relation of findings joined to advisories (as HostFindingGroups').
  def initialize(scope, after: nil, before: nil, per_page: PER_PAGE)
    @scope = scope
    @per_page = per_page
    cursor = before || after
    @notice = :invalid if cursor == :invalid
    cursor = nil if cursor == :invalid
    load(cursor, !before.nil? && !cursor.nil?)
  end

  def paged? = previous || self.next

  private

  def load(cursor, backwards)
    rows = read(cursor, backwards)
    if cursor && rows.empty?
      @notice = :moved
      return load(nil, false)
    end
    return load(nil, false) if backwards && rows.size <= @per_page

    @advisory_count = rows.first&.fetch("advisories").to_i
    @finding_count = rows.first&.fetch("findings").to_i
    page = rows.first(@per_page)
    page.reverse! if backwards
    @groups = build(page)
    @previous = cursor ? cursor_of(page.first) : nil
    @next = backwards || rows.size > @per_page ? cursor_of(page.last) : nil
  end

  def cursor_of(row) = [ row["severity_rank"], row["kev_rank"], row["advisory_key"] ].join(",")

  # The page's advisories (one more, to tell whether there is a next page) past the cursor, with the totals over every
  # advisory, in one query.
  def read(cursor, backwards)
    aggregated = @scope.except(:order, :preload, :includes).reselect(
      Arel.sql("advisories.id AS advisory_ref"), Arel.sql("advisories.advisory_id AS advisory_key"),
      Arel.sql("max(CASE WHEN vulnerability_findings.kev THEN 1 ELSE 0 END) AS kev_rank"),
      Arel.sql("min(array_position(ARRAY['critical', 'high', 'medium', 'low', 'unknown']::varchar[], advisories.severity)) AS severity_rank"),
      Arel.sql("count(*) AS finding_rows")
    ).group("advisories.id", "advisories.advisory_id")
    totalled = VulnerabilityFinding.unscoped.from("g").select(Arel.sql("g.*"), Arel.sql("count(*) OVER () AS advisories, sum(g.finding_rows) OVER () AS findings"))
    query = VulnerabilityFinding.unscoped.with(g: aggregated, r: totalled).from("r g").select(Arel.sql("g.*"))
    query = query.where("(#{KEY}) #{backwards ? '<' : '>'} #{CURSOR_KEY}", *cursor) if cursor
    order = KEY.split(", ").map { |key| backwards ? Arel.sql(key).desc : Arel.sql(key) }
    VulnerabilityFinding.connection.select_all(query.order(*order).limit(@per_page + 1).arel, "HostAdvisoryGroups").to_a
  end

  # The page's advisories with their findings, in one query. An advisory with none left is left off.
  def build(rows)
    return [] if rows.empty?

    page = @scope.where(advisory_id: rows.map { |row| row["advisory_ref"] })
    findings = VulnerabilityFinding.with_details_of(page).preload(:advisory).to_a.group_by(&:advisory_id)
    rows.filter_map do |row|
      list = findings[row["advisory_ref"]] or next

      Group.new(advisory: list.first.advisory, findings: list.sort_by { |f| [ f.package, f.architecture ] })
    end
  end
end
