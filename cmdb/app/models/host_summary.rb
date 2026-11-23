# What the summary tiles under a host's header show on every tab (P2-D02 to P2-D04, owner decision Q1 on the
# P2-D01 review): the host's CIS-aligned pass rate, its vulnerability exposure and work remaining (VT-SCORES #262,
# epic decision 18: they replace the open count and the Packages tile, whose count the Packages tab shows), when each
# report type last arrived and whether it is on schedule (ReportSchedule), and its open tasks by state for the Tasks
# tab (P3-DASH-TASKS). A fixed number of queries.
class HostSummary
  REPORT_TYPES = %w[config packages inventory].freeze

  attr_reader :cis, :package_set, :vulnerability_evaluation, :open_by_severity, :open_by_bucket, :received, :open_tasks,
              :intervals, :now, :scores, :work_done, :work_cleared, :badges

  def initialize(host, now: Time.current)
    @now = now
    @first_seen_at = host.first_seen_at
    @intervals = ReportSchedule.intervals
    @cis = CisCompliance.for_host(host.id)
    @package_set = HostPackageSet.find_by(host_id: host.id)
    @vulnerability_evaluation = HostVulnerabilityEvaluation.find_by(host_id: host.id)
    # By severity and triage bucket in one query (VT-HOST-TAB #260: the tab bar's "N to act on").
    by_bucket = VulnerabilityFinding.active.where(host_id: host.id).joins(:advisory).group("advisories.severity", :bucket).count
    @open_by_severity = by_bucket.group_by { |(severity, _), _| severity }.transform_values { |rows| rows.sum(&:last) }
    @open_by_bucket = by_bucket.group_by { |(_, bucket), _| VulnerabilityTriage.bucket_for(bucket) }.transform_values { |rows| rows.sum(&:last) }
    @received = { "config" => HostConfig.where(host_id: host.id).pick(:received_at), "packages" => @package_set&.received_at,
                  "inventory" => HostInventory.where(host_id: host.id).pick(:received_at) }
    @open_tasks = Task.open_now.where(host_id: host.id).group(:state).count
    load_scores(host.id)
  end

  # KEV's freshness, for the tier's qualifier (read when the tile is drawn).
  def kev_status = @kev_status ||= Signals::Freshness.status(Signals::KEV, now:)

  # Findings that are open or reopened.
  def open_findings = open_by_severity.values.sum

  # [[severity, count], ...] from critical to unknown, leaving out severities with none.
  def open_severities = Advisory::SEVERITIES.filter_map { |severity| [ severity, open_by_severity[severity] ] if open_by_severity[severity] }

  # Open findings in Fix available or Needs attention (epic decision 17), or nil while any open finding has no bucket
  # yet (the upgrade's background re-triage has not reached the host, #277 item 15): then no count stands for them.
  def to_act_on = open_by_bucket.key?(nil) ? nil : open_by_bucket.values_at("fix", "attention").sum(&:to_i)

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

  private

  # The host's exposure and work from its summary row (VulnerabilityExposure::Scores; nil before the row exists), the
  # work events of the last HostVulnerabilityWork::WINDOW for the tile's progress, and the badge settings: three
  # queries.
  def load_scores(host_id)
    row = HostComplianceSummary.find_by(host_id:)
    @scores = row && VulnerabilityExposure::Scores.from(row, packages_received_at: received["packages"])
    @work_done, cleared = VulnerabilityWorkEvent.where(host_id:, occurred_at: (now - HostVulnerabilityWork::WINDOW)..now)
                                                .pick(Arel.sql("count(*)"), Arel.sql("COALESCE(sum(findings_cleared), 0)"))
    @work_cleared = cleared.to_i
    @badges = Setting.vulnerability_badges
  end
end
