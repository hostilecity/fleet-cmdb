# One page of a host's findings for one package (P2-D04's package page; #283, a follow-up of VT-HOST-TAB #281). The
# tab draws at most HostTriageSections::NESTED_MAX findings under a package row and links here for the rest, so a
# package with thousands of findings (a running kernel's) is paged here rather than drawn whole.
#
# - Order: worst severity first, then the earliest first seen, then the advisory id (bytewise, "C" collation), then the
#   finding's id: the order the tab draws a package row's findings in, so the tab's "N more" link can start here
#   right after the last finding it drew (cursor_of).
# - Pages: keyset pages of PER_PAGE findings after (or before) a cursor holding the whole sort key, as #253's package
#   rows and HostAdvisoryGroups do: a cursor that does not parse, or one with nothing past it any more, reads the first
#   page and says so (notice). The page is one query (its rows picked and sorted on the plain findings table, then
#   their details looked up for those rows only, #302) and its advisories one more; the count of every finding the
#   filters keep one more, unless the caller has it already (count: the package's whole count, with no filter); and the page's triage inputs (VulnerabilityTriage::Explain, for the reasons) and its CVEs'
#   KEV dates and EPSS scores a fixed number, so the page costs the same statements whatever the package's size.
#
# scope: the findings shown, a relation of findings joined to advisories (the controller's filters applied): the plain
# table, or with details when a filter reads one (VulnerabilityFinding.with_host_details). host_id: the host they are of. The reasons' helper (triage_reason) reads inputs, kev_dates, epss_scores, and decisions, as on
# HostTriageSections. decisions: the host's HostDecisions (VT-OVERRIDES #261), so a finding here shows the decision tags
# it has on the tab: O1's control and its link, a Low risk finding's decision, and a Needs attention finding's, which
# the tab shows in its Decision column.
class HostPackageFindings
  PER_PAGE = 50 # as the tab's pages (HostFindingGroups, HostAdvisoryGroups)
  CURSOR_MAX = 200
  ID = HostAdvisoryGroups::ID

  KEY = 'vulnerability_findings.severity_rank, vulnerability_findings.first_seen_at, vulnerability_findings.advisory_key COLLATE "C", vulnerability_findings.id'.freeze
  CURSOR_KEY = '(?::integer, ?::timestamp, ? COLLATE "C", ?::bigint)'.freeze
  RANK_SQL = "array_position(ARRAY['critical', 'high', 'medium', 'low', 'unknown']::varchar[], advisories.severity)".freeze
  # KEY over a finding joined to its advisory, to sort the page's rows read with their details.
  ROW_KEY = [ RANK_SQL, "vulnerability_findings.first_seen_at", 'advisories.advisory_id COLLATE "C"', "vulnerability_findings.id" ].freeze

  attr_reader :findings, :previous, :next, :count, :notice, :inputs, :kev_dates, :epss_scores, :decisions

  # The cursor a parameter names: nil when none, :invalid when it does not parse, else [severity rank, first seen,
  # advisory id, finding id].
  def self.cursor(value)
    value = value.to_s
    return nil if value.empty?
    return :invalid if value.length > CURSOR_MAX

    rank, seen, advisory, id = value.split(",", 4)
    return :invalid unless rank.to_s.match?(/\A[1-5]\z/) && ID.match?(advisory.to_s) && id.to_s.match?(/\A\d{1,18}\z/)

    [ rank.to_i, Time.iso8601(seen.to_s).utc, advisory, id.to_i ]
  rescue ArgumentError
    :invalid
  end

  # The cursor of a loaded finding (its advisory loaded): the page after it starts with the finding that sorts next.
  def self.cursor_of(finding)
    [ Advisory::SEVERITIES.index(finding.advisory.severity) + 1, finding.first_seen_at.utc.iso8601(6), finding.advisory.advisory_id, finding.id ].join(",")
  end

  def initialize(scope, host_id:, after: nil, before: nil, per_page: PER_PAGE, count: nil, decisions: nil, now: Time.current)
    @scope = scope
    @host_id = host_id
    @decisions = decisions
    @per_page = per_page
    cursor = before || after
    @notice = :invalid if cursor == :invalid
    cursor = nil if cursor == :invalid
    @count = count || scope.except(:order, :preload, :includes).count
    load(cursor, !before.nil? && !cursor.nil?)
    load_details(now)
  end

  def paged? = previous || self.next

  private

  def load(cursor, backwards)
    rows = read(cursor, backwards)
    if cursor && rows.empty?
      @notice = :moved # nothing past the cursor any more: the findings changed since the link was drawn
      return load(nil, false)
    end
    return load(nil, false) if backwards && rows.size <= @per_page # Previous to the first page, full

    page = rows.first(@per_page)
    page.reverse! if backwards
    @findings = page
    @previous = cursor && page.any? ? self.class.cursor_of(page.first) : nil
    @next = page.any? && (backwards || rows.size > @per_page) ? self.class.cursor_of(page.last) : nil
  end

  # The page's findings (one more, to tell whether there is a next page) past the cursor, in one query, and their
  # advisories in one more (preload). The rows are picked on the scope with their sort key (KEY), then read again with
  # their details and sorted by the same key (ROW_KEY), so the details are looked up for those rows only (#302).
  def read(cursor, backwards)
    keyed = @scope.except(:order, :preload, :includes).select(Arel.sql("vulnerability_findings.id"), Arel.sql("vulnerability_findings.first_seen_at"),
                                                              Arel.sql("#{RANK_SQL} AS severity_rank"), Arel.sql("advisories.advisory_id AS advisory_key"))
    page = VulnerabilityFinding.unscoped.from(keyed, :vulnerability_findings)
    page = page.where("(#{KEY}) #{backwards ? '<' : '>'} #{CURSOR_KEY}", *cursor) if cursor
    page = page.order(*ordered(KEY.split(", "), backwards)).limit(@per_page + 1)
    VulnerabilityFinding.with_details_of(page, host_id: @host_id).joins(:advisory).preload(:advisory).order(*ordered(ROW_KEY, backwards)).to_a
  end

  def ordered(parts, backwards) = parts.map { |part| backwards ? Arel.sql(part).desc : Arel.sql(part) }

  def load_details(now)
    @inputs = VulnerabilityTriage::Explain.load(findings, now:)
    cves = @inputs.values.flat_map(&:cve_ids).uniq
    @kev_dates = cves.empty? ? {} : KevEntry.where(cve_id: cves).pluck(:cve_id, :date_added).to_h
    @epss_scores = cves.empty? ? {} : EpssScore.where(cve_id: cves).pluck(:cve_id, :score).to_h
  end
end
