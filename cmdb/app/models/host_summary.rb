# What the summary tiles under a host's header show on every tab (P2-D02 to P2-D04, owner decision Q1 on the
# P2-D01 review): the host's CIS-aligned pass rate, its open vulnerability findings by severity (or why it was not
# evaluated), its package count and manager, when each report type last arrived and whether it is on schedule
# (ReportSchedule), and its open tasks by state for the Tasks tab (P3-DASH-TASKS). A fixed number of queries.
class HostSummary
  REPORT_TYPES = %w[config packages inventory].freeze

  attr_reader :cis, :package_set, :packages_changed_at, :vulnerability_evaluation, :open_by_severity, :received, :open_tasks,
              :intervals, :now

  def initialize(host, now: Time.current)
    @now = now
    @first_seen_at = host.first_seen_at
    @intervals = ReportSchedule.intervals
    @cis = CisCompliance.for_host(host.id)
    @package_set = HostPackageSet.find_by(host_id: host.id)
    @packages_changed_at = PackageSnapshot.where(host_id: host.id).maximum(:received_at)
    @vulnerability_evaluation = HostVulnerabilityEvaluation.find_by(host_id: host.id)
    @open_by_severity = VulnerabilityFinding.active.where(host_id: host.id).joins(:advisory).group("advisories.severity").count
    @received = { "config" => HostConfig.where(host_id: host.id).pick(:received_at), "packages" => @package_set&.received_at,
                  "inventory" => HostInventory.where(host_id: host.id).pick(:received_at) }
    @open_tasks = Task.open_now.where(host_id: host.id).group(:state).count
  end

  # Findings that are open or reopened.
  def open_findings = open_by_severity.values.sum

  # [[severity, count], ...] from critical to unknown, leaving out severities with none.
  def open_severities = Advisory::SEVERITIES.filter_map { |severity| [ severity, open_by_severity[severity] ] if open_by_severity[severity] }

  # A host is evaluated for vulnerabilities only once matching has run and found it evaluable.
  def vulnerabilities_evaluated? = vulnerability_evaluation.present? && !vulnerability_evaluation.not_evaluated?

  # Whether any report has arrived.
  def any_received? = received.values.any?

  # Each report type's state against its interval (ReportSchedule): :on_schedule, :overdue, :missing, or :awaited.
  def report_state(type)
    ReportSchedule.state(received_at: received[type], interval: intervals.fetch(type), first_seen_at: @first_seen_at, now:)
  end

  # The report types in a state, in the order of REPORT_TYPES.
  def report_types(state) = REPORT_TYPES.select { |type| report_state(type) == state }
end
