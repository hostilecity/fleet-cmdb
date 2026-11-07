# The fleet compliance view (P2-D05, FR-2.5; approved mockup compliance.html): every active host with its CIS-aligned pass
# rate, its open CIS-aligned check failures by severity, and its open vulnerability findings by severity, and the same
# counts for the whole fleet. Built from query parameters so every view is linkable, as FleetList is: q (name or hostname),
# tag, status, cis and vuln (a severity, from the fleet-wide counts), sort, and page.
#
# Everything is counted in the database from the rows the host pages show: CIS results with the severity of the rule
# version that produced them (the current version when a result names none), as the Configuration tab does, and open or
# reopened findings with their advisory's severity, as the Vulnerabilities tab does. The pass rate is the host page's,
# passed / (passed + failed + not readable) (CisCompliance, owner decision Q3). A page is a fixed number of queries
# whatever the fleet size: the rows, their count, the fleet-wide totals, the tags, and HostContext for hosts matching
# has not run on yet.
#
# Not evaluated is never zero. CIS-aligned checks are not evaluated on a host with no pass, fail, or not readable result
# (no rules, no config report). Vulnerabilities are not evaluated on a host whose last matching run could not evaluate
# it, or before matching has run; findings kept from an earlier evaluation are still open, and are still counted, as on
# the host's tab.
class FleetCompliance
  CIS_SEVERITIES = %w[critical high medium low].freeze
  VULN_SEVERITIES = Advisory::SEVERITIES

  STATUSES = {
    "attention" => "Has open failures or findings",
    "critical_high" => "Has critical or high",
    "clean" => "No open findings",
    "not_evaluated" => "Not evaluated"
  }.freeze

  SORTS = { "worst" => "Worst first", "pass_rate" => "Lowest CIS pass rate", "vulns" => "Most open vulnerabilities", "name" => "Name" }.freeze

  PER_PAGE = 100
  QUERY_MAX = 100

  # Per-host counts, as lateral joins on hosts so a page reads only its own hosts' rows (indexes on host_id). Each
  # aggregate without GROUP BY gives one row, so a host with no results or findings has zeros, never NULLs. Written out
  # in full (one column per severity in CIS_SEVERITIES and VULN_SEVERITIES; a spec checks they match) so no SQL is built.
  JOINS = <<~SQL.squish.freeze
    LEFT JOIN LATERAL (
      SELECT count(*) FILTER (WHERE r.result = 'pass') AS cis_passed,
             count(*) FILTER (WHERE r.result = 'fail') AS cis_failed,
             count(*) FILTER (WHERE r.result = 'not_readable') AS cis_not_readable,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'critical') AS cis_critical,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'high') AS cis_high,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'medium') AS cis_medium,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'low') AS cis_low
      FROM cis_results r
      JOIN cis_rules ru ON ru.id = r.cis_rule_id
      LEFT JOIN cis_rule_versions rv ON rv.id = r.cis_rule_version_id
      LEFT JOIN cis_rule_versions cv ON cv.id = ru.current_version_id
      WHERE r.host_id = hosts.id
    ) cis ON true
    LEFT JOIN LATERAL (
      SELECT count(*) FILTER (WHERE a.severity = 'critical') AS vuln_critical,
             count(*) FILTER (WHERE a.severity = 'high') AS vuln_high,
             count(*) FILTER (WHERE a.severity = 'medium') AS vuln_medium,
             count(*) FILTER (WHERE a.severity = 'low') AS vuln_low,
             count(*) FILTER (WHERE a.severity = 'unknown') AS vuln_unknown
      FROM vulnerability_findings f
      JOIN advisories a ON a.id = f.advisory_id
      WHERE f.host_id = hosts.id AND f.state IN ('open', 'reopened')
    ) vulns ON true
    LEFT JOIN host_vulnerability_evaluations hve ON hve.host_id = hosts.id
    LEFT JOIN host_configs hc ON hc.host_id = hosts.id
    LEFT JOIN host_package_sets hps ON hps.host_id = hosts.id
  SQL

  COLUMNS = [
    "cis.*", "vulns.*", "hve.state AS vuln_state", "hve.reason AS vuln_reason", "hve.ecosystem AS vuln_ecosystem",
    "hc.received_at AS config_received_at", "hps.received_at AS packages_received_at"
  ].freeze

  # Expressions over the columns above, for the outer query (the per-host rows are a subquery named hosts).
  CIS_COUNTED = "(hosts.cis_passed + hosts.cis_failed + hosts.cis_not_readable)".freeze
  PASS_RATE = "(hosts.cis_passed::numeric / NULLIF(#{CIS_COUNTED}, 0))".freeze
  VULN_OPEN = "(#{VULN_SEVERITIES.map { |s| "hosts.vuln_#{s}" }.join(' + ')})".freeze
  VULN_EVALUATED = "(hosts.vuln_state IS NOT DISTINCT FROM 'evaluated')".freeze
  VULN_SHOWN = "(#{VULN_EVALUATED} OR #{VULN_OPEN} > 0)".freeze
  NOTHING_EVALUATED = "(#{CIS_COUNTED} = 0 AND NOT #{VULN_SHOWN})".freeze
  # CIS failures and vulnerabilities of one severity together, for worst first (owner decision Q9).
  BOTH = ->(severity) { severity == "unknown" ? "hosts.vuln_unknown" : "(hosts.cis_#{severity} + hosts.vuln_#{severity})" }

  STATUS_FILTERS = {
    "attention" => "hosts.cis_failed > 0 OR #{VULN_OPEN} > 0",
    "critical_high" => "#{BOTH.('critical')} + #{BOTH.('high')} > 0",
    "clean" => "#{CIS_COUNTED} > 0 AND #{VULN_EVALUATED} AND hosts.cis_failed = 0 AND #{VULN_OPEN} = 0",
    "not_evaluated" => "#{CIS_COUNTED} = 0 OR NOT #{VULN_EVALUATED}"
  }.freeze
  CIS_FILTERS = CIS_SEVERITIES.to_h { |s| [ s, "hosts.cis_#{s} > 0" ] }.freeze
  VULN_FILTERS = VULN_SEVERITIES.to_h { |s| [ s, "hosts.vuln_#{s} > 0" ] }.freeze

  NAME_ORDER = [ Arel.sql("lower(hosts.name)").asc, Arel.sql("hosts.id").asc ].freeze
  # Hosts with nothing evaluated at all sit below everything (Q9); then most critical, high, medium, low, and unknown,
  # then lowest pass rate.
  ORDERS = {
    "worst" => [ Arel.sql(NOTHING_EVALUATED).asc, *VULN_SEVERITIES.map { |s| Arel.sql(BOTH.(s)).desc }, Arel.sql(PASS_RATE).asc.nulls_last ],
    "pass_rate" => [ Arel.sql(PASS_RATE).asc.nulls_last ],
    "vulns" => [ Arel.sql(VULN_SHOWN).desc, Arel.sql(VULN_OPEN).desc, *VULN_SEVERITIES.map { |s| Arel.sql("hosts.vuln_#{s}").desc } ],
    "name" => []
  }.transform_values { |order| (order + NAME_ORDER).freeze }.freeze

  # One host's compliance, as the page and the fleet list show it. cis and vulns are { severity => open count }.
  Row = Data.define(:host, :cis_passed, :cis_counted, :cis, :vulns, :vulns_evaluated, :vuln_reason, :vuln_ecosystem,
                    :config_received_at, :packages_received_at) do
    def cis_evaluated? = cis_counted.positive?
    def pass_rate = cis_evaluated? ? cis_passed.fdiv(cis_counted) : nil
    def cis_failed = cis.values.sum
    def vulns_evaluated? = vulns_evaluated
    def vulns_open = vulns.values.sum
    # Counts are shown when matching evaluated the host, or when findings from an earlier evaluation are still open.
    def vulns_shown? = vulns_evaluated? || vulns_open.positive?
    def nothing_evaluated? = !cis_evaluated? && !vulns_shown?
    def config_report? = !config_received_at.nil?
  end

  # Fleet-wide open counts over every active host, whatever the filters, so they equal the sum of the unfiltered table.
  Totals = Data.define(:hosts, :cis_evaluated, :cis_passed, :cis_counted, :cis, :vulns_evaluated, :vulns) do
    def cis_failed = cis.values.sum
    def vulns_open = vulns.values.sum
    def pass_rate = cis_counted.positive? ? cis_passed.fdiv(cis_counted) : nil
    def vulns_not_evaluated = hosts - vulns_evaluated
  end

  attr_reader :q, :tag, :status, :cis, :vuln, :sort

  def initialize(params = {})
    @q = params[:q].to_s.strip.first(QUERY_MAX).presence
    @tag = params[:tag].present? ? Host.normalize_tag(params[:tag]) : nil
    @status = STATUSES.key?(params[:status]) ? params[:status] : nil
    @cis = CIS_FILTERS.key?(params[:cis]) ? params[:cis] : nil
    @vuln = VULN_FILTERS.key?(params[:vuln]) ? params[:vuln] : nil
    @sort = SORTS.key?(params[:sort]) ? params[:sort] : "worst"
    @requested_page = [ params[:page].to_i, 1 ].max
  end

  # Active hosts with their per-host counts as extra attributes; scope narrows the hosts (FleetList passes its own).
  def self.with_counts(scope) = scope.joins(JOINS).select("hosts.*", *COLUMNS)

  # The per-host rows as a relation named hosts, so the expressions above can filter and sort them.
  def self.per_host(scope = Host.active) = Host.from(with_counts(scope), :hosts)

  # { host_id => Row } for hosts loaded through with_counts, with HostContext for the ones matching has not run on.
  def self.rows_for(hosts)
    unmatched = hosts.select { |host| host.vuln_state.nil? }.map(&:id)
    contexts = unmatched.empty? ? {} : HostContext.load(unmatched).index_by(&:host_id)
    hosts.to_h { |host| [ host.id, row(host, contexts[host.id]) ] }
  end

  def self.row(host, context)
    cis = CIS_SEVERITIES.index_with { |s| host.public_send(:"cis_#{s}") }
    vulns = VULN_SEVERITIES.index_with { |s| host.public_send(:"vuln_#{s}") }
    Row.new(host:, cis_passed: host.cis_passed, cis_counted: host.cis_passed + host.cis_failed + host.cis_not_readable, cis:, vulns:,
            vulns_evaluated: host.vuln_state == "evaluated", vuln_reason: host.vuln_state ? host.vuln_reason : context&.reason,
            vuln_ecosystem: host.vuln_ecosystem || context&.ecosystem,
            config_received_at: host.config_received_at, packages_received_at: host.packages_received_at)
  end

  def self.totals
    sums = [ "count(*)", "count(*) FILTER (WHERE #{CIS_COUNTED} > 0)", "sum(hosts.cis_passed)", "sum(#{CIS_COUNTED})",
             *CIS_SEVERITIES.map { |s| "sum(hosts.cis_#{s})" }, "count(*) FILTER (WHERE #{VULN_EVALUATED})",
             *VULN_SEVERITIES.map { |s| "sum(hosts.vuln_#{s})" } ]
    values = per_host.pick(*sums.map { |sql| Arel.sql("COALESCE(#{sql}, 0)") }).map(&:to_i)
    hosts, cis_evaluated, cis_passed, cis_counted = values.shift(4)
    cis = CIS_SEVERITIES.zip(values.shift(CIS_SEVERITIES.size)).to_h
    vulns_evaluated = values.shift
    Totals.new(hosts:, cis_evaluated:, cis_passed:, cis_counted:, cis:, vulns_evaluated:, vulns: VULN_SEVERITIES.zip(values).to_h)
  end

  def self.tags = Host.active.distinct.pluck(Arel.sql("unnest(hosts.tags)")).sort

  def scope
    hosts = Host.active
    hosts = hosts.where("hosts.name ILIKE :p OR hosts.hostname ILIKE :p", p: "%#{Host.sanitize_sql_like(q)}%") if q
    hosts = hosts.tagged(tag) if tag
    relation = self.class.per_host(hosts)
    relation = relation.where(STATUS_FILTERS.fetch(status)) if status
    relation = relation.where(CIS_FILTERS.fetch(cis)) if cis
    relation = relation.where(VULN_FILTERS.fetch(vuln)) if vuln
    relation
  end

  def total = @total ||= scope.count
  def pages = [ (total + PER_PAGE - 1) / PER_PAGE, 1 ].max
  def page = [ @requested_page, pages ].min
  def first_row = total.zero? ? 0 : (page - 1) * PER_PAGE + 1
  def last_row = [ page * PER_PAGE, total ].min

  def rows
    @rows ||= self.class.rows_for(scope.order(*ORDERS.fetch(sort)).offset((page - 1) * PER_PAGE).limit(PER_PAGE).to_a).values
  end

  def filtered? = [ q, tag, status, cis, vuln ].any?

  # Query parameters for a link, keeping the filters and the sort unless changed (nil removes one). Defaults are left out.
  def params_with(**changes)
    { q:, tag:, status:, cis:, vuln:, sort: (sort unless sort == "worst") }.merge(changes).compact
  end

  def aria_sort(column) = sort == column ? "ascending" : "none"
end
