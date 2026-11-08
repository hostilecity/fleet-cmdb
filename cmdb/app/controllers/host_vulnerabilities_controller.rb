# A host's Vulnerabilities tab and the findings for one package (P2-D04, FR-2.4, FR-2.5; approved mockups
# host-vulns.html, host-vuln-package.html, states-packages-vulns.html). Read-only.
#
# - Findings grouped by binary package with the advisories nested under it (owner decision Q16): the package row
#   shows the worst severity and the number of findings shown; the severity filter matches single advisories.
#   Filterable by state (open and reopened by default, resolved, all), severity, and text (package, source package,
#   or advisory id).
# - A host that is not evaluated says so and why (HostVulnerabilityEvaluation, or HostContext before matching has
#   run), never an empty list; findings kept from an earlier evaluation say they may be out of date. Packages the
#   matcher could not check are listed. Advisory data freshness (Advisories::Freshness, P2-S13) is shown.
# - package: every finding for one package name on the host, with when it was first seen, resolved, and reopened.
# - Debian's triage (P2-D08, ADR 0022; owner decisions T1 to T8 on #134): FindingTriage for the page's findings, in
#   a fixed number of queries. The tab shows it under the advisory on open and reopened rows, with the "Debian: no
#   security update planned" chip (debian=no_dsa, open and reopened findings, counted within that state) and a
#   notice when the host release's triage is stale; the package page shows it on every row. It never changes a
#   finding's state, severity, the filters, or any count.
class HostVulnerabilitiesController < ApplicationController
  include HostTab

  STATES = %w[open resolved all].freeze
  QUERY_MAX = 100

  # One binary package's findings as shown: the package, the findings in display order, and the worst severity.
  Group = Data.define(:package, :architecture, :findings) do
    def worst = findings.first.advisory.severity
    def installed_version = findings.first.installed_version
  end

  before_action :load_host_tab

  def show
    load_evaluation
    findings = VulnerabilityFinding.where(host_id: @host.id)
    @state_counts = { "open" => findings.active.count, "resolved" => findings.where(state: "resolved").count }
    @state_counts["all"] = @state_counts.values.sum
    @state = STATES.include?(params[:state]) ? params[:state] : "open"
    @severity = Advisory::SEVERITIES.include?(params[:severity]) ? params[:severity] : nil
    @query = params[:q].to_s.strip.first(QUERY_MAX)
    # The chip narrows the open and reopened list, the rows that show Debian's triage (T3, T5).
    @debian = params[:debian] == "no_dsa" && @state == "open" ? "no_dsa" : nil
    # Every matching finding is loaded and grouped in Ruby, without a limit (review of #124): a host has one finding per
    # installed binary package and advisory that affects it, a few hundred at most on a 3,000-package host with
    # current updates, and the groups need every finding of a package to show its worst severity. Page the groups,
    # as HostPackageList pages packages, if hosts with thousands of findings appear.
    shown = filtered(findings).to_a
    load_tab_triage(findings, shown)
    shown = shown.select { |f| helpers.triage_no_dsa?(@triage[f]) } if @debian
    @open_groups = groups(shown.select { |f| f.state != "resolved" })
    @resolved_groups = groups(shown.select { |f| f.state == "resolved" })
    @advisory_count = AdvisoryPackage.where(ecosystem: @evaluation.ecosystem).distinct.count(:advisory_id) if @evaluation && !@evaluation.not_evaluated?
  end

  def package
    @package = params[:package].to_s
    @installed = HostPackage.where(host_id: @host.id, name: @package).order(:architecture).to_a
    @findings = sorted(VulnerabilityFinding.where(host_id: @host.id, package: @package).includes(:advisory).to_a)
    raise ActiveRecord::RecordNotFound, "the host has no such package and no finding for it" if @installed.empty? && @findings.empty?

    load_evaluation
    @set = @package_set
    @evaluated = @evaluation.present? && !@evaluation.not_evaluated?
    # The package and advisory pairs the matcher could not compare for this package, and whether the list it keeps was cut
    # short, so that this package may be among the ones it no longer shows (review of #120).
    @unchecked = @evaluated ? @evaluation.not_evaluated.select { |entry| entry["package"] == @package } : []
    @unchecked_cut_short = @evaluated && @evaluation.not_evaluated_count > @evaluation.not_evaluated.size
    @ecosystem = @findings.first&.ecosystem || HostVulnerabilityEvaluation.where(host_id: @host.id).pick(:ecosystem)
    sources = (@installed.map(&:source) + @findings.map(&:source)).compact.uniq
    @siblings = VulnerabilityFinding.where(host_id: @host.id, source: sources).where.not(package: @package).distinct.order(:package).pluck(:package)
    load_triage_context
    @triage = FindingTriage.load(@findings) # every row, as today's note (T5)
  end

  private

  # The host's release and its triage freshness, for the freshness line, the stale notice, and the stale reason's
  # date (T8). One query.
  def load_triage_context
    @triage_os = @host.inventory&.stable&.dig("os")
    @triage_release = DebianTriage::Releases.for_os(@triage_os)
    @triage_status = @triage_release && DebianTriage::Freshness.statuses.find { |status| status.release == @triage_release }
  end

  # Triage for the open and reopened findings the tab can show (T5), and the chip's count over all of them in the
  # state filter, whatever the severity and search filters (T3). On the default list (open, no filters) those are
  # the findings shown; otherwise the open and reopened findings are loaded once more. None on the resolved list.
  def load_tab_triage(findings, shown)
    load_triage_context
    @triage = nil
    return if @state == "resolved"

    active = if @state == "open" && @severity.nil? && @query.blank? then shown
    elsif @state == "open" then findings.active.includes(:advisory).to_a
    else shown.reject { |f| f.state == "resolved" }
    end
    @triage = FindingTriage.load(active)
    @no_dsa_count = active.count { |f| helpers.triage_no_dsa?(@triage[f]) } if @state == "open"
  end

  def load_evaluation
    @evaluation = HostVulnerabilityEvaluation.find_by(host_id: @host.id)
    @context = HostContext.load([ @host.id ]).first unless @evaluation
    @freshness = Advisories::Freshness.statuses
    @package_set = HostPackageSet.find_by(host_id: @host.id)
  end

  def filtered(findings)
    scope = findings.joins(:advisory).includes(:advisory)
    scope = scope.where(state: @state == "open" ? %w[open reopened] : "resolved") unless @state == "all"
    scope = scope.where(advisories: { severity: @severity }) if @severity
    if @query.present?
      pattern = "%#{VulnerabilityFinding.sanitize_sql_like(@query)}%"
      scope = scope.where("vulnerability_findings.package ILIKE :p OR vulnerability_findings.source ILIKE :p OR advisories.advisory_id ILIKE :p", p: pattern)
    end
    scope
  end

  # Severity, worst first, then the earliest first seen.
  def sorted(findings) = findings.sort_by { |f| [ Advisory::SEVERITIES.index(f.advisory.severity), f.first_seen_at, f.advisory.advisory_id ] }

  def groups(findings)
    findings.group_by { |f| [ f.package, f.architecture ] }
            .map { |(package, architecture), list| Group.new(package:, architecture:, findings: sorted(list)) }
            .sort_by { |group| [ Advisory::SEVERITIES.index(group.worst), group.findings.map(&:first_seen_at).min, group.package, group.architecture ] }
  end
end
