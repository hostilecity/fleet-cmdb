# The fleet list and its counts (FR-1.5, P1-D02). Built from query parameters so every view is linkable:
# q (name or hostname), tag, status, sort, and dir. Retired hosts are never listed or counted. Each list is
# two queries whatever the fleet size: one for the rows (with the OS name joined in) and one for the counts.
class FleetList
  # Display statuses: liveness for active hosts, enrollment state otherwise (FR-1.1, FR-1.4).
  STATUSES = {
    "online" => "Online",
    "stale" => "Stale",
    "offline" => "Offline",
    "awaiting" => "Awaiting first contact",
    "pending" => "Pending enrollment",
    "revoked" => "Credential revoked"
  }.freeze

  STATUS_RANK = <<~SQL.squish.freeze
    CASE
      WHEN hosts.enrollment_state = 'active' AND hosts.liveness_status = 'online' THEN 0
      WHEN hosts.enrollment_state = 'active' AND hosts.liveness_status = 'stale' THEN 1
      WHEN hosts.enrollment_state = 'active' AND hosts.liveness_status = 'offline' THEN 2
      WHEN hosts.enrollment_state = 'active' THEN 3
      WHEN hosts.enrollment_state = 'pending' THEN 4
      ELSE 5
    END
  SQL

  SORTS = {
    "name" => "lower(hosts.name)",
    "status" => STATUS_RANK,
    "last_seen" => "hosts.last_seen_at",
    "hostname" => "hosts.hostname",
    "os" => "lower(host_inventories.stable #>> '{os,pretty_name}')",
    # Numeric by release (0.10.0 after 0.9.0); pre-release and build suffixes are ignored.
    "agent" => "string_to_array(regexp_replace(hosts.agent_version, '[-+].*$', ''), '.')::int[]"
  }.freeze

  # Every ORDER BY clause the list can use, built from the constants above only.
  ORDERS = SORTS.transform_values do |sql|
    expression = Arel.sql(sql)
    { "asc" => expression.asc.nulls_last, "desc" => expression.desc.nulls_last }.freeze
  end.freeze

  attr_reader :q, :tag, :status, :sort, :direction

  def initialize(params = {})
    @q = params[:q].to_s.strip.first(100).presence
    @tag = params[:tag].present? ? Host.normalize_tag(params[:tag]) : nil
    @status = STATUSES.key?(params[:status]) ? params[:status] : nil
    @sort = SORTS.key?(params[:sort]) ? params[:sort] : "name"
    @direction = params[:dir] == "desc" ? "desc" : "asc"
  end

  # Fleet rows (with os_name) for the given host ids, for live updates.
  def self.rows(ids) = base_scope.where(id: ids).to_a

  def self.base_scope
    Host.in_fleet.left_joins(:inventory).select("hosts.*", "host_inventories.stable #>> '{os,pretty_name}' AS os_name")
  end

  def hosts
    scope = self.class.base_scope
    scope = scope.where("hosts.name ILIKE :p OR hosts.hostname ILIKE :p", p: "%#{Host.sanitize_sql_like(q)}%") if q
    scope = scope.tagged(tag) if tag
    scope = filter_status(scope) if status
    scope.order(ORDERS.fetch(sort).fetch(direction), Arel.sql("lower(hosts.name)"), :id)
  end

  # Counts for the status strip: active hosts by liveness, pending and revoked apart. Ignores the filters.
  def self.counts
    totals = Host.in_fleet.group(:enrollment_state, :liveness_status).count
    active = ->(liveness) { totals.fetch([ "active", liveness ], 0) }
    {
      "online" => active.("online"), "stale" => active.("stale"), "offline" => active.("offline"), "awaiting" => active.(nil),
      "pending" => totals.select { |(state, _), _| state == "pending" }.values.sum,
      "revoked" => totals.select { |(state, _), _| state == "revoked" }.values.sum
    }
  end

  def self.tags = Host.in_fleet.distinct.pluck(Arel.sql("unnest(hosts.tags)")).sort

  # The display status key for one host, matching STATUSES.
  def self.status_of(host)
    case host.enrollment_state
    when "active" then host.liveness_status || "awaiting"
    when "pending" then "pending"
    else host.enrollment_state
    end
  end

  def filtered? = q.present? || tag.present? || status.present?

  # Query parameters for a link that sorts by column, toggling direction when it is already the sort.
  def sort_params(column)
    dir = sort == column && direction == "asc" ? "desc" : "asc"
    { q:, tag:, status:, sort: column, dir: }.compact
  end

  def aria_sort(column)
    return "none" unless sort == column

    direction == "asc" ? "ascending" : "descending"
  end

  private

  def filter_status(scope)
    case status
    when "online", "stale", "offline" then scope.where(enrollment_state: "active", liveness_status: status)
    when "awaiting" then scope.where(enrollment_state: "active", liveness_status: nil)
    else scope.where(enrollment_state: status)
    end
  end
end
