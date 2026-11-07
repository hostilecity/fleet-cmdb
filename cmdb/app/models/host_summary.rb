# What the summary tiles under a host's header show on every tab (P2-D02 to P2-D04, owner decision Q1 on the
# P2-D01 review): the host's CIS-aligned pass rate, its open vulnerability findings by severity (or why it was not
# evaluated), its package count and manager, and when each report type last arrived. A fixed number of queries.
class HostSummary
  REPORT_TYPES = %w[config packages inventory].freeze

  attr_reader :cis, :package_set, :packages_changed_at, :vulnerability_evaluation, :open_by_severity, :received

  def initialize(host)
    @cis = CisCompliance.for_host(host.id)
    @package_set = HostPackageSet.find_by(host_id: host.id)
    @packages_changed_at = PackageSnapshot.where(host_id: host.id).maximum(:received_at)
    @vulnerability_evaluation = HostVulnerabilityEvaluation.find_by(host_id: host.id)
    @open_by_severity = VulnerabilityFinding.active.where(host_id: host.id).joins(:advisory).group("advisories.severity").count
    @received = { "config" => HostConfig.where(host_id: host.id).pick(:received_at), "packages" => @package_set&.received_at,
                  "inventory" => HostInventory.where(host_id: host.id).pick(:received_at) }
  end

  # Findings that are open or reopened.
  def open_findings = open_by_severity.values.sum

  # [[severity, count], ...] from critical to unknown, leaving out severities with none.
  def open_severities = Advisory::SEVERITIES.filter_map { |severity| [ severity, open_by_severity[severity] ] if open_by_severity[severity] }

  # A host is evaluated for vulnerabilities only once matching has run and found it evaluable.
  def vulnerabilities_evaluated? = vulnerability_evaluation.present? && !vulnerability_evaluation.not_evaluated?

  # The newest report of any type, or nil when none has arrived.
  def last_received_at = received.values.compact.max

  # The report types received, newest first, and the ones never received.
  def received_types = received.select { |_, at| at }.sort_by { |_, at| -at.to_f }.map(&:first)
  def missing_types = REPORT_TYPES - received_types
end
