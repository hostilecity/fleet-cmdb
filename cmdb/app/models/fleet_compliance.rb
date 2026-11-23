# The fleet compliance view (P2-D05, FR-2.5; approved mockup compliance.html): every active host with its CIS-aligned pass
# rate, its open CIS-aligned check failures by severity, and its open vulnerability findings by severity, and the same
# counts for the whole fleet. Built from query parameters so every view is linkable, as FleetList is: q (name or hostname),
# tag, ecosystem (a distribution release such as Debian:13), status, cis and vuln (a severity, from the fleet-wide counts),
# bucket (a triage bucket: hosts with open findings in it; VT-SCORES #262, replacing VT-FIXABLE's fix filter), sort, and
# a keyset cursor, after or before (#193).
#
# The counts are each host's HostComplianceSummary, which the database keeps from the rows the host pages show: CIS
# results with the severity of the rule version that produced them (the current version when a result names none), as
# the Configuration tab does, and open or reopened findings with their advisory's severity, as the Vulnerabilities tab
# does, with their triage buckets (VT-BUCKETS #259) and the exposure tier, points, and work items (VT-SCORES #262). The
# pass rate is the host page's, passed / (passed + failed + not readable) (CisCompliance, owner decision Q3).
# A page reads its 100 rows in index order for each sort, after the cursor host (KeysetPage), so it costs the same
# whatever the fleet size and however deep the page; the fleet-wide counts are one sum over the summaries. A page is a
# fixed number of queries: the rows, their reports and evaluations, the count of a filtered list, the totals, the
# tags, and HostContext for hosts matching has not run on yet.
#
# Not evaluated is never zero. CIS-aligned checks are not evaluated on a host with no pass, fail, or not readable result
# (no rules, no config report). Vulnerabilities are not evaluated on a host whose last matching run could not evaluate
# it, or before matching has run; findings kept from an earlier evaluation are still open, and are still counted, as on
# the host's tab. A host that is not evaluated is never counted as having a fix (#252 question 6): its summary counts
# none.
class FleetCompliance
  CIS_SEVERITIES = %w[critical high medium low].freeze
  VULN_SEVERITIES = Advisory::SEVERITIES

  STATUSES = {
    "attention" => "Has open failures or findings",
    "critical_high" => "Has critical or high",
    "clean" => "No open findings",
    "not_evaluated" => "Not evaluated"
  }.freeze

  # The bucket line under the severity strip and its filter (VT-SCORES #262, VT-D06): the summary's finding count per
  # triage bucket, the four adding up to the open count.
  BUCKETS = { "fix" => "vuln_fix", "attention" => "vuln_attention", "low_risk" => "vuln_low_risk", "ignorable" => "vuln_ignorable" }.freeze

  SORTS = { "worst" => "Worst first", "pass_rate" => "Lowest CIS pass rate", "vulns" => "Most open vulnerabilities", "name" => "Name" }.freeze

  PER_PAGE = 100
  QUERY_MAX = 100

  # Each host's summary row, named summaries in every query that reads it.
  SUMMARIES = "JOIN host_compliance_summaries summaries ON summaries.host_id = hosts.id".freeze
  COUNTS = %w[cis_passed cis_failed cis_not_readable cis_critical cis_high cis_medium cis_low
              vuln_critical vuln_high vuln_medium vuln_low vuln_unknown vuln_evaluated vuln_low_risk vuln_ignorable
              exposure_tier exposure_points vuln_kev_advisories vuln_fix_critical vuln_attention_undecided vuln_attention vuln_fix
              work_upgrades work_kernel_install work_reboot work_items fixable_critical_since no_fixable_critical_since].uniq.freeze
  COLUMNS = COUNTS.map { |column| "summaries.#{column}" }.freeze
  # Both, so the planner can use the fleet list's indexes (partial on hosts in the fleet) for the shared sorts.
  ACTIVE = "summaries.enrollment_state = 'active' AND summaries.enrollment_state <> 'retired'".freeze
  # CIS failures and vulnerabilities of one severity together, for worst first and the critical or high filter (Q9).
  BOTH = ->(severity) { severity == "unknown" ? "summaries.vuln_unknown" : "(summaries.cis_#{severity} + summaries.vuln_#{severity})" }

  STATUS_FILTERS = {
    "attention" => "summaries.cis_failed > 0 OR summaries.vuln_open > 0",
    "critical_high" => "#{BOTH.('critical')} + #{BOTH.('high')} > 0",
    "clean" => "summaries.cis_counted > 0 AND summaries.vuln_evaluated AND summaries.cis_failed = 0 AND summaries.vuln_open = 0",
    "not_evaluated" => "summaries.cis_counted = 0 OR NOT summaries.vuln_evaluated"
  }.freeze
  CIS_FILTERS = CIS_SEVERITIES.to_h { |s| [ s, "summaries.cis_#{s} > 0" ] }.freeze
  VULN_FILTERS = VULN_SEVERITIES.to_h { |s| [ s, "summaries.vuln_#{s} > 0" ] }.freeze
  # bucket=<bucket>: an open finding in that bucket (with vuln, both: a finding of that severity and one in that bucket).
  BUCKET_FILTERS = BUCKETS.transform_values { |column| "summaries.#{column} > 0" }.freeze

  NAME = KeysetPage::Key.new(sql: "summaries.name_key")
  ID = KeysetPage::Key.new(sql: "summaries.host_id")
  # Each sort's keys, every one backed by an index on host_compliance_summaries. Worst first (Q9): hosts with nothing
  # evaluated at all sit below everything; then most critical, high, medium, low, and unknown, then lowest pass rate;
  # every key ascending (counts negated, no pass rate as 2), so it is the index host_compliance_summaries_worst.
  # Lowest pass rate and most open vulnerabilities are the fleet list's compliance columns, which are NULL (last) for
  # hosts not evaluated. Ties go by name, as every sort's do (review of #128).
  KEYS = {
    "worst" => [ "summaries.nothing_evaluated", *VULN_SEVERITIES.map { |s| "(- #{BOTH.(s)})" }, "COALESCE(summaries.pass_rate, 2::numeric)" ]
               .map { |sql| KeysetPage::Key.new(sql:) },
    "pass_rate" => [ KeysetPage::Key.new(sql: "summaries.fleet_cis_key", nullable: true) ],
    "vulns" => [ KeysetPage::Key.new(sql: "summaries.fleet_vulns_key", descending: true, nullable: true) ],
    "name" => []
  }.transform_values { |keys| (keys + [ NAME, ID ]).freeze }.freeze

  # One host's compliance, as the page and the fleet list show it. cis and vulns are { severity => open count }; buckets
  # { bucket => open count }; scores its VulnerabilityExposure::Scores.
  Row = Data.define(:host, :cis_passed, :cis_counted, :cis, :vulns, :vulns_evaluated, :vuln_reason, :vuln_ecosystem,
                    :config_received_at, :packages_received_at, :buckets, :scores) do
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
  # buckets: open findings per bucket; work_items: the scored hosts' work items.
  Totals = Data.define(:hosts, :cis_evaluated, :cis_passed, :cis_counted, :cis, :vulns_evaluated, :vulns, :buckets, :work_items) do
    def cis_failed = cis.values.sum
    def vulns_open = vulns.values.sum
    def pass_rate = cis_counted.positive? ? cis_passed.fdiv(cis_counted) : nil
    def vulns_not_evaluated = hosts - vulns_evaluated
  end

  attr_reader :q, :tag, :ecosystem, :status, :cis, :vuln, :bucket, :sort

  def initialize(params = {})
    @q = params[:q].to_s.strip.first(QUERY_MAX).presence
    @tag = params[:tag].present? ? Host.normalize_tag(params[:tag]) : nil
    @status = STATUSES.key?(params[:status]) ? params[:status] : nil
    @cis = CIS_FILTERS.key?(params[:cis]) ? params[:cis] : nil
    @vuln = VULN_FILTERS.key?(params[:vuln]) ? params[:vuln] : nil
    @bucket = BUCKETS.key?(params[:bucket]) ? params[:bucket] : nil
    @ecosystem = Ecosystems.supported?(params[:ecosystem]) ? params[:ecosystem] : nil
    @sort = SORTS.key?(params[:sort]) ? params[:sort] : "worst"
    @cursor = KeysetPage.cursor(params)
  end

  # Hosts with their summary's counts as extra attributes; scope narrows the hosts (FleetList passes its own).
  def self.with_counts(scope) = scope.joins(SUMMARIES).select("hosts.*", *COLUMNS)

  # Active hosts with their counts, unordered.
  def self.per_host(scope = Host.active) = with_counts(scope).where(ACTIVE)

  # { host_id => Row } for hosts loaded through with_counts: one more query for their vulnerability evaluations and
  # last reports, and HostContext for the ones matching has not run on.
  def self.rows_for(hosts)
    return {} if hosts.empty?

    ActiveRecord::Associations::Preloader.new(records: hosts, associations: :liveness).call # the status lamps
    details = Host.where(id: hosts.map(&:id)).joins(DETAILS)
                  .pluck(:id, "hve.state", "hve.reason", "hve.ecosystem", "hc.received_at", "hps.received_at").to_h { |id, *rest| [ id, rest ] }
    unmatched = hosts.reject { |host| details.dig(host.id, 0) }.map(&:id)
    contexts = unmatched.empty? ? {} : HostContext.load(unmatched).index_by(&:host_id)
    hosts.to_h { |host| [ host.id, row(host, details.fetch(host.id), contexts[host.id]) ] }
  end

  DETAILS = <<~SQL.squish.freeze
    LEFT JOIN host_vulnerability_evaluations hve ON hve.host_id = hosts.id
    LEFT JOIN host_configs hc ON hc.host_id = hosts.id
    LEFT JOIN host_package_sets hps ON hps.host_id = hosts.id
  SQL

  def self.row(host, details, context)
    vuln_state, vuln_reason, vuln_ecosystem, config_received_at, packages_received_at = details
    cis = CIS_SEVERITIES.index_with { |s| host.public_send(:"cis_#{s}") }
    vulns = VULN_SEVERITIES.index_with { |s| host.public_send(:"vuln_#{s}") }
    Row.new(host:, cis_passed: host.cis_passed, cis_counted: host.cis_passed + host.cis_failed + host.cis_not_readable, cis:, vulns:,
            vulns_evaluated: host.vuln_evaluated, vuln_reason: vuln_state ? vuln_reason : context&.reason,
            vuln_ecosystem: vuln_ecosystem || context&.ecosystem, config_received_at:, packages_received_at:,
            buckets: BUCKETS.transform_values { |column| host.public_send(column) },
            scores: VulnerabilityExposure::Scores.from(host, packages_received_at:))
  end

  # One sum over the active hosts' summaries.
  def self.totals
    sums = [ "count(*)", "count(*) FILTER (WHERE cis_counted > 0)", "sum(cis_passed)", "sum(cis_counted)",
             *CIS_SEVERITIES.map { |s| "sum(cis_#{s})" }, "count(*) FILTER (WHERE vuln_evaluated)",
             *VULN_SEVERITIES.map { |s| "sum(vuln_#{s})" }, *BUCKETS.values.map { |column| "sum(#{column})" }, "sum(work_items)" ]
    values = HostComplianceSummary.where(enrollment_state: "active").pick(*sums.map { |sql| Arel.sql("COALESCE(#{sql}, 0)") }).map(&:to_i)
    hosts, cis_evaluated, cis_passed, cis_counted = values.shift(4)
    cis = CIS_SEVERITIES.zip(values.shift(CIS_SEVERITIES.size)).to_h
    vulns_evaluated = values.shift
    vulns = VULN_SEVERITIES.zip(values.shift(VULN_SEVERITIES.size)).to_h
    buckets = BUCKETS.keys.zip(values.shift(BUCKETS.size)).to_h
    Totals.new(hosts:, cis_evaluated:, cis_passed:, cis_counted:, cis:, vulns_evaluated:, vulns:, buckets:, work_items: values.first)
  end

  # The ids of hosts whose inventory reports a distribution release in the ecosystem (Ecosystems::TABLE, DEC-01), as a
  # subquery: the Data sources page's "Hosts using it" links here (owner decision on #128).
  def self.running(ecosystem)
    releases = Ecosystems::TABLE.select { |_, e| e == ecosystem }.keys
    releases.map { |id, version| HostInventory.where("lower(stable -> 'os' ->> 'id') = ? AND stable -> 'os' ->> 'version_id' = ?", id, version) }
            .reduce(:or).select(:host_id)
  end

  def self.tags = FleetList.tags_of(HostComplianceSummary.where(enrollment_state: "active"))

  def scope
    hosts = Host.active
    hosts = hosts.where("hosts.name ILIKE :p OR hosts.hostname ILIKE :p", p: "%#{Host.sanitize_sql_like(q)}%") if q
    hosts = hosts.tagged(tag) if tag
    hosts = hosts.where(id: self.class.running(ecosystem)) if ecosystem
    relation = self.class.per_host(hosts)
    relation = relation.where(STATUS_FILTERS.fetch(status)) if status
    relation = relation.where(CIS_FILTERS.fetch(cis)) if cis
    relation = relation.where(VULN_FILTERS.fetch(vuln)) if vuln
    relation = relation.where(BUCKET_FILTERS.fetch(bucket)) if bucket
    relation
  end

  # Hosts matching the filters: the page's "of N".
  def total = @total ||= scope.count(:all)

  def page
    @page ||= KeysetPage.new(scope:, keys: KEYS.fetch(sort), lookup: Host.joins(SUMMARIES), per_page: PER_PAGE, **@cursor)
  end

  def rows = @rows ||= self.class.rows_for(page.rows).values

  def filtered? = [ q, tag, ecosystem, status, cis, vuln, bucket ].any?

  # Whether the page was asked for by a cursor (Previous or Next), so an empty page may only mean its hosts moved on.
  def cursor? = @cursor.any?

  # Query parameters for a link, keeping the filters and the sort unless changed (nil removes one). Defaults are left out,
  # and so is the cursor: a changed filter or sort starts at the first page.
  def params_with(**changes)
    { q:, tag:, ecosystem:, status:, cis:, vuln:, bucket:, sort: (sort unless sort == "worst") }.merge(changes).compact
  end

  def aria_sort(column) = sort == column ? "ascending" : "none"
end
