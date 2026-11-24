# The fleet list and its counts (FR-1.5, P1-D02). Built from query parameters so every view is linkable:
# q (name or hostname), tag, status, recovery (#232), vulns (VT-SCORES #262), restarts (#251), sort, dir, and a keyset cursor, after or
# before (#193). Retired hosts are never
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
  # Exposure and Work (VT-SCORES #262, VT-D06, owner decision 19), highest first only: by tier, then points (so one
  # known exploited host always ranks above any number of medium findings, S6), or by work items; then name. Hosts not
  # active or not scored (not evaluated, or not triaged yet) are NULL and sort last. Each is one index on the summaries
  # (host_compliance_summaries_exposure and _work), read in order.
  ACTIVE_KEY = "CASE WHEN summaries.enrollment_state::text = 'active'::text THEN %s END".freeze
  RANKED = {
    "exposure" => [ format(ACTIVE_KEY, "summaries.exposure_tier"), format(ACTIVE_KEY, "summaries.exposure_points") ],
    "work" => [ format(ACTIVE_KEY, "summaries.work_items") ]
  }.freeze

  # The vulnerabilities filter (VT-D06): active hosts that are scored, by their summary, or not evaluated now.
  SCORED = "summaries.enrollment_state = 'active' AND summaries.exposure_tier IS NOT NULL".freeze
  VULN_FILTERS = {
    "known_exploited" => [ "Known exploited (not ignorable)", "#{SCORED} AND summaries.exposure_tier = 4" ],
    "attention" => [ "Has findings that need attention", "#{SCORED} AND summaries.vuln_attention > 0" ],
    "fix" => [ "Has a fix available", "#{SCORED} AND summaries.vuln_fix > 0" ],
    "nothing_to_install" => [ "Nothing to install", "#{SCORED} AND summaries.work_items = 0" ],
    "not_evaluated" => [ "Not evaluated", "summaries.enrollment_state = 'active' AND NOT summaries.vuln_evaluated" ]
  }.freeze
  # "Nothing to install" is claimed only where the cell says it: not on a host whose package report is older than the
  # badge setting, which reads "Not known" (review of #305, S6).
  FRESH_REPORT = "EXISTS (SELECT 1 FROM host_package_sets p WHERE p.host_id = summaries.host_id AND p.received_at >= ?)".freeze

  COLUMNS = [ "hosts.*", "summaries.os_name", *FleetCompliance::COLUMNS ].freeze

  # The recovery-mode filter (#232): active hosts that have sent a heartbeat and do not report recovery mode as set up
  # (Host#recovery_mode_coverage :not_set_up, :unchecked, or :not_reported). Matches the partial index
  # index_hosts_without_recovery_mode, so it reads only those hosts.
  RECOVERY_FILTERS = { "missing" => "Not set up" }.freeze
  WITHOUT_RECOVERY_MODE = "hosts.enrollment_state = 'active' AND hosts.first_seen_at IS NOT NULL AND hosts.agent_recovery_coverage IS DISTINCT FROM 'set_up'".freeze

  # The restart-loop filter (#251): hosts whose agent systemd restarted more than the restart-loop limit within its
  # window (config.x.restart_loop, 3 times in 24 hours by default). agent_restart_loop_at is the (limit + 1)th newest
  # restart, within the window exactly when there were more than limit; it is the partial index index_hosts_restart_loops,
  # so the page reads only the hosts that loop, whatever the fleet's size (review of #307, S1). The array condition is
  # the same rule read from agent_recent_restarts, for a host whose column was stored under a higher limit; after
  # lowering FLEET_RESTART_LOOP_RESTARTS, `bin/rails restart_loops:refresh` (Host.refresh_restart_loops!) stores it again.
  RESTART_FILTERS = %w[loop].freeze
  RESTART_LOOP = "hosts.agent_restart_loop_at >= :since AND hosts.agent_recent_restarts[:position] >= :since".freeze

  attr_reader :q, :tag, :status, :recovery, :vulns, :restarts, :sort, :direction

  def initialize(params = {})
    @q = params[:q].to_s.strip.first(100).presence
    @tag = params[:tag].present? ? Host.normalize_tag(params[:tag]) : nil
    @status = STATUSES.key?(params[:status]) ? params[:status] : nil
    @recovery = RECOVERY_FILTERS.key?(params[:recovery]) ? params[:recovery] : nil
    @vulns = VULN_FILTERS.key?(params[:vulns]) ? params[:vulns] : nil
    @sort = SORTS.key?(params[:sort]) || RANKED.key?(params[:sort]) ? params[:sort] : "name"
    @direction = RANKED.key?(@sort) || params[:dir] == "desc" ? "desc" : "asc"
    @restarts = RESTART_FILTERS.include?(params[:restarts]) ? params[:restarts] : nil
    @cursor = KeysetPage.cursor(params)
  end

  def self.base_scope = Host.in_fleet.joins(FleetCompliance::SUMMARIES).joins(LIVENESS).where(IN_FLEET).select(*COLUMNS)

  # The fleet in the filters, unordered.
  def scope
    scope = self.class.base_scope
    scope = scope.where("hosts.name ILIKE :p OR hosts.hostname ILIKE :p", p: "%#{Host.sanitize_sql_like(q)}%") if q
    scope = scope.tagged(tag) if tag
    scope = scope.where(summaries: { status_rank: STATUS_RANKS.fetch(status) }) if status
    scope = scope.where(WITHOUT_RECOVERY_MODE) if recovery
    scope = scope.where(VULN_FILTERS.fetch(vulns).last) if vulns
    scope = scope.where(FRESH_REPORT, Time.current - Setting.vulnerability_badges[:report_max_age]) if vulns == "nothing_to_install"
    scope = scope.where(RESTART_LOOP, since: Time.current - Rollouts.restart_loop.window, position: Rollouts.restart_loop.limit + 1) if restarts
    scope
  end

  # The restart filter's words, with the settings in force: "More than 3 times in 24 hours".
  def self.restart_filter_label
    settings = Rollouts.restart_loop
    "More than #{ActionController::Base.helpers.pluralize(settings.limit, 'time')} in #{ActionController::Base.helpers.pluralize(settings.window.in_hours.to_i, 'hour')}"
  end

  def keys
    if RANKED.key?(sort)
      return [ *RANKED.fetch(sort).map { |sql| KeysetPage::Key.new(sql:, descending: true, nullable: true) }, FleetCompliance::NAME, FleetCompliance::ID ]
    end

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

  def filtered? = q.present? || tag.present? || status.present? || recovery.present? || vulns.present? || restarts.present?

  # Only the recovery-mode filter is set: an empty list then means every active host is covered (#232).
  def only_recovery_filter? = recovery.present? && q.blank? && tag.blank? && status.blank? && vulns.blank? && restarts.blank?

  # Only the restart filter is set: an empty list then means no agent is in a restart loop (#251).
  def only_restart_filter? = restarts.present? && q.blank? && tag.blank? && status.blank? && recovery.blank? && vulns.blank?

  # Whether the page was asked for by a cursor (Previous or Next), so an empty page may only mean its hosts moved on.
  def cursor? = @cursor.any?

  # Query parameters for a link that sorts by column, toggling direction when it is already the sort (Exposure and
  # Work sort highest first only). A new sort starts at the first page.
  def sort_params(column)
    dir = RANKED.key?(column) || (sort == column && direction == "asc") ? "desc" : "asc"
    { q:, tag:, status:, recovery:, vulns:, restarts:, sort: column, dir: (dir unless RANKED.key?(column)) }.compact
  end

  # The filters and sort, defaults left out, for the pager's links (which add a cursor) and the first page.
  def list_params
    { q:, tag:, status:, recovery:, vulns:, restarts:, sort: (sort unless sort == "name"), dir: (direction unless direction == "asc" || RANKED.key?(sort)) }.compact
  end

  def aria_sort(column)
    return "none" unless sort == column

    direction == "asc" ? "ascending" : "descending"
  end
end
