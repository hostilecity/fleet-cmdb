# A host's Vulnerabilities tab and the findings for one package (P2-D04, FR-2.4, FR-2.5; approved mockups
# host-vulns.html, host-vuln-package.html, states-packages-vulns.html). Read-only.
#
# - Findings grouped by binary package with the advisories nested under it (owner decision Q16): the package row
#   shows the worst severity and the number of findings shown; the severity filter matches single advisories.
#   Filterable by state (open and reopened by default, resolved, all), severity, and text (package, source package,
#   or advisory id). One page of ROWS_PER_PAGE rows is drawn at a time; the counts are of every finding shown.
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
  # Finding rows drawn on one page of the tab. A page holds whole groups where it can; a package with more findings
  # than are left on the page goes on over the next page, its package row repeated and marked as continued.
  ROWS_PER_PAGE = 200
  SEVERITY_RANK = Advisory::SEVERITIES.each_with_index.to_h.freeze

  # One binary package's findings as shown: the package, the findings in display order, and the worst severity.
  # rows: the findings drawn on this page (all of them unless the group spans pages); continued: the page starts
  # partway through the group.
  Group = Data.define(:package, :architecture, :findings, :rows, :continued) do
    def initialize(package:, architecture:, findings:, rows: findings, continued: false) = super
    def worst = findings.first.advisory.severity
    def installed_version = findings.first.installed_version
  end

  reads_from_replica only: %i[show package] # a caught-up replica when one is configured (#198)
  before_action :load_host_tab

  def show
    load_evaluation
    findings = VulnerabilityFinding.with_details.where(host_id: @host.id)
    # Counted on the findings alone, in one query: the details' joins add no rows (#254).
    by_state = VulnerabilityFinding.where(host_id: @host.id).group(:state).count
    @state_counts = { "open" => by_state.values_at("open", "reopened").compact.sum, "resolved" => by_state.fetch("resolved", 0) }
    @state_counts["all"] = @state_counts.values.sum
    @state = STATES.include?(params[:state]) ? params[:state] : "open"
    @severity = Advisory::SEVERITIES.include?(params[:severity]) ? params[:severity] : nil
    @query = params[:q].to_s.strip.first(QUERY_MAX)
    # The chip narrows the open and reopened list, the rows that show Debian's triage (T3, T5).
    @debian = params[:debian] == "no_dsa" && @state == "open" ? "no_dsa" : nil
    # Every matching finding is loaded and grouped in Ruby (review of #124): the groups need every finding of a package
    # to show its worst severity, and the headings and chips count them all. Only one page of rows is drawn
    # (ROWS_PER_PAGE, open groups first): a Debian host with current advisory data has thousands of findings (unfixed
    # CVEs in the kernel, glibc, systemd, ...), and drawing them all made the tab megabytes long and slow to load.
    shown = filtered(findings).to_a
    load_tab_triage(findings, shown)
    shown = shown.select { |f| helpers.triage_no_dsa?(@triage[f]) } if @debian
    @open_groups = groups(shown.select { |f| f.state != "resolved" })
    @resolved_groups = groups(shown.select { |f| f.state == "resolved" })
    page_groups
    @advisory_count = AdvisoryPackage.where(ecosystem: @evaluation.ecosystem).distinct.count(:advisory_id) if @evaluation && !@evaluation.not_evaluated?
  end

  def package
    @package = params[:package].to_s
    load_evaluation
    @installed = PackageStore.entries(PackageStore.chunk_ids_of(@package_set&.package_set_id), names: [ @package ])
    @findings = sorted(VulnerabilityFinding.with_details.where(host_id: @host.id, package: @package).preload(:advisory).to_a)
    raise ActiveRecord::RecordNotFound, "the host has no such package and no finding for it" if @installed.empty? && @findings.empty?

    @set = @package_set
    @evaluated = @evaluation.present? && !@evaluation.not_evaluated?
    # The package and advisory pairs the matcher could not compare for this package, and whether the list it keeps was cut
    # short, so that this package may be among the ones it no longer shows (review of #120).
    @unchecked = @evaluated ? @evaluation.not_evaluated.select { |entry| entry["package"] == @package } : []
    @unchecked_cut_short = @evaluated && @evaluation.not_evaluated_count > @evaluation.not_evaluated.size
    @ecosystem = @findings.first&.ecosystem || HostVulnerabilityEvaluation.where(host_id: @host.id).pick(:ecosystem)
    sources = (@installed.map(&:source) + @findings.map(&:source)).compact.uniq
    @siblings = VulnerabilityFinding.with_details.where(host_id: @host.id, source: sources).where.not(package: @package).distinct.order(:package).pluck(:package)
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
    elsif @state == "open" then findings.active.preload(:advisory).to_a
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
    scope = findings.joins(:advisory).preload(:advisory)
    scope = scope.where(state: @state == "open" ? %w[open reopened] : "resolved") unless @state == "all"
    scope = scope.where(advisories: { severity: @severity }) if @severity
    if @query.present?
      pattern = "%#{VulnerabilityFinding.sanitize_sql_like(@query)}%"
      scope = scope.where("vulnerability_findings.package ILIKE :p OR vulnerability_findings.source ILIKE :p OR advisories.advisory_id ILIKE :p", p: pattern)
    end
    scope
  end

  # Severity, worst first, then the earliest first seen.
  def sorted(findings) = findings.sort_by { |f| [ SEVERITY_RANK.fetch(f.advisory.severity), f.first_seen_at, f.advisory.advisory_id ] }

  # The pager's links: the filters as they are, on another page (the first page has no page parameter).
  def page_params(page)
    { state: (@state unless @state == "open"), severity: @severity, q: @query.presence, debian: @debian, page: (page if page > 1) }.compact
  end
  helper_method :page_params

  # One page of the rows shown, open groups first, then resolved ones (state=all shows both): @open_page and
  # @resolved_page are this page's groups of each, with the rows on it; @row_count is every row shown, and @pages and
  # @page the pager's.
  def page_groups
    sequence = (@state == "resolved" ? [] : @open_groups) + (@state == "open" ? [] : @resolved_groups)
    @row_count = sequence.sum { |group| group.findings.size }
    @pages = [ (@row_count + ROWS_PER_PAGE - 1) / ROWS_PER_PAGE, 1 ].max
    @page = params[:page].to_i.clamp(1, @pages)
    @first_row = @row_count.zero? ? 0 : ((@page - 1) * ROWS_PER_PAGE) + 1
    @last_row = [ @page * ROWS_PER_PAGE, @row_count ].min
    @open_page, @resolved_page = [], []
    offset = 0
    sequence.each do |group|
      size = group.findings.size
      from, to = [ @first_row - 1 - offset, 0 ].max, [ @last_row - offset, size ].min
      offset += size
      next if to <= from

      shown = group.with(rows: group.findings[from...to], continued: from.positive?)
      (group.findings.first.state == "resolved" ? @resolved_page : @open_page) << shown
      break if offset >= @last_row
    end
  end

  def groups(findings)
    findings.group_by { |f| [ f.package, f.architecture ] }
            .map { |(package, architecture), list| Group.new(package:, architecture:, findings: sorted(list)) }
            .sort_by { |group| [ SEVERITY_RANK.fetch(group.worst), group.findings.map(&:first_seen_at).min, group.package, group.architecture ] }
  end
end
