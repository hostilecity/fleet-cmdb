# The fleet list and its counts (FR-1.5, P1-D02). Built from query parameters so every view is linkable:
# q (name or hostname), tag, status, sort, dir, and a keyset cursor, after or before (#193). Retired hosts are never
# listed or counted. A page is 100 rows read in index order after the cursor host (KeysetPage), from each host's
# HostComplianceSummary, which carries the sort keys, the operating system name, and FleetCompliance's counts, so the
# list costs the same whatever the fleet size; the counts are one more query over the summaries.
class FleetList
  PER_PAGE = 100

  # Display statuses: liveness for active hosts, enrollment state otherwise (FR-1.1, FR-1.4). Their order is the status
  # sort's, the summary's status_rank (db/functions/host_compliance_summaries_sync_v01.sql).
  STATUSES = {
    "online" => "Online",
    "stale" => "Stale",
    "offline" => "Offline",
    "awaiting" => "Awaiting first contact",
    "pending" => "Pending enrollment",
    "revoked" => "Credential revoked"
  }.freeze
  STATUS_RANKS = STATUSES.keys.each_with_index.to_h.freeze

  IN_FLEET = "summaries.enrollment_state <> 'retired'".freeze
  # The host's heartbeat state, for the "last seen" sort (#192). LEFT: a host awaiting first contact has none. The
  # planner drops the join from every query that does not read it.
  LIVENESS = "LEFT JOIN host_liveness liveness ON liveness.host_id = hosts.id".freeze

  # Each sort's key and whether it can be NULL (sorted last in either direction); ties go by name, then id. Every key
  # but last seen has an index on host_compliance_summaries in each direction. Last seen sorts the filtered fleet by
  # host_liveness.last_seen_at, which changes on every heartbeat: an index on it would make every heartbeat a
  # non-HOT update with two index entries, so it has none (ADR 0029).
  SORTS = {
    "name" => [ "summaries.name_key", false ],
    "status" => [ "summaries.status_rank", false ],
    "last_seen" => [ "liveness.last_seen_at", true ],
    "hostname" => [ "summaries.hostname", false ],
    "os" => [ "lower(summaries.os_name)", true ],
    # Numeric by release (0.10.0 after 0.9.0), pre-release and build suffixes ignored (review of #53).
    "agent" => [ "summaries.agent_key", true ],
    # By the tag list as displayed (in entry order); hosts without tags sort last in either direction.
    "tags" => [ "summaries.tags_key", true ],
    # The two compliance columns (P2-D05, owner decision Q8). Hosts that are not active or not evaluated sort last in
    # either direction, so they are never taken for 0% or for no findings.
    "cis" => [ "summaries.fleet_cis_key", true ],
    "vulns" => [ "summaries.fleet_vulns_key", true ]
  }.freeze

  COLUMNS = [ "hosts.*", "summaries.os_name", *FleetCompliance::COLUMNS ].freeze

  attr_reader :q, :tag, :status, :sort, :direction

  def initialize(params = {})
    @q = params[:q].to_s.strip.first(100).presence
    @tag = params[:tag].present? ? Host.normalize_tag(params[:tag]) : nil
    @status = STATUSES.key?(params[:status]) ? params[:status] : nil
    @sort = SORTS.key?(params[:sort]) ? params[:sort] : "name"
    @direction = params[:dir] == "desc" ? "desc" : "asc"
    @cursor = KeysetPage.cursor(params)
  end

  def self.base_scope = Host.in_fleet.joins(FleetCompliance::SUMMARIES).joins(LIVENESS).where(IN_FLEET).select(*COLUMNS)

  # The fleet in the filters, unordered.
  def scope
    scope = self.class.base_scope
    scope = scope.where("hosts.name ILIKE :p OR hosts.hostname ILIKE :p", p: "%#{Host.sanitize_sql_like(q)}%") if q
    scope = scope.tagged(tag) if tag
    scope = scope.where(summaries: { status_rank: STATUS_RANKS.fetch(status) }) if status
    scope
  end

  def keys
    sql, nullable = SORTS.fetch(sort)
    key = KeysetPage::Key.new(sql:, descending: direction == "desc", nullable:)
    sort == "name" ? [ key, FleetCompliance::ID ] : [ key, FleetCompliance::NAME, FleetCompliance::ID ]
  end

  def page
    @page ||= KeysetPage.new(scope:, keys:, lookup: Host.joins(FleetCompliance::SUMMARIES).joins(LIVENESS), per_page: PER_PAGE, **@cursor)
  end

  # This page's hosts, with os_name, the compliance counts, and their liveness (one more query for the page).
  def hosts = @hosts ||= page.rows.tap { |rows| ActiveRecord::Associations::Preloader.new(records: rows, associations: :liveness).call }

  # Hosts matching the filters: the page's "of N" when the list is filtered (the status strip counts the whole fleet).
  def total = @total ||= scope.count(:all)

  # Counts for the status strip: active hosts by liveness, pending and revoked apart. Ignores the filters. One
  # query over the summaries, which are much narrower than hosts.
  def self.counts
    totals = HostComplianceSummary.where.not(enrollment_state: "retired").group(:status_rank).count
    STATUS_RANKS.transform_values { |rank| totals.fetch(rank, 0) }
  end

  # The tags in use, from the summaries' tag lists, which are much narrower than hosts (a tag never holds a comma:
  # Host::TAG_FORMAT).
  def self.tags = tags_of(HostComplianceSummary.where.not(enrollment_state: "retired"))

  def self.tags_of(summaries) = summaries.distinct.pluck(Arel.sql("unnest(string_to_array(tags_key, ','))")).sort

  # The display status key for one host, matching STATUSES.
  def self.status_of(host)
    case host.enrollment_state
    when "active" then host.liveness_status || "awaiting"
    when "pending" then "pending"
    else host.enrollment_state
    end
  end

  def filtered? = q.present? || tag.present? || status.present?

  # Whether the page was asked for by a cursor (Previous or Next), so an empty page may only mean its hosts moved on.
  def cursor? = @cursor.any?

  # Query parameters for a link that sorts by column, toggling direction when it is already the sort. A new sort
  # starts at the first page.
  def sort_params(column)
    dir = sort == column && direction == "asc" ? "desc" : "asc"
    { q:, tag:, status:, sort: column, dir: }.compact
  end

  # The filters and sort, defaults left out, for the pager's links (which add a cursor) and the first page.
  def list_params = { q:, tag:, status:, sort: (sort unless sort == "name"), dir: (direction unless direction == "asc") }.compact

  def aria_sort(column)
    return "none" unless sort == column

    direction == "asc" ? "ascending" : "descending"
  end
end
