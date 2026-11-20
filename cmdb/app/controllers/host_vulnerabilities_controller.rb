# A host's Vulnerabilities tab and the findings for one package (P2-D04, FR-2.4, FR-2.5; approved mockups
# host-vulns.html, host-vuln-package.html, states-packages-vulns.html). Read-only.
#
# - Findings grouped by binary package (owner decision Q16), one row per package with its advisories collapsed under
#   it (owner request): the row shows how many advisories it has, the worst
#   severity, how many have a fix available (open list) or how they resolved (resolved list), and their states;
#   HostFindingGroups ranks and pages them (see there). The severity filter matches single advisories. Filterable by state (open and reopened by default, resolved, all),
#   severity, and text (package, source package, or advisory id); a text search opens the groups it finds.
# - A host that is not evaluated says so and why (HostVulnerabilityEvaluation, or HostContext before matching has
#   run), never an empty list; findings kept from an earlier evaluation say they may be out of date. Packages the
#   matcher could not check are listed. Advisory data freshness (Advisories::Freshness, P2-S13) is shown.
# - package: every finding for one package name on the host, with when it was first seen, resolved, and reopened.
# - Fix availability (VT-FIXABLE #256, folding in #252): on the open and reopened list, "Fix available" and "No fix
#   available" chips (fix=available or fix=none) filter by the finding's stored fix flag, combined with the other
#   filters. They are counted over the whole open list whatever the severity, text, and triage filters, in the state
#   counts' query, so they add up to the open count; package rows count only the findings the filter keeps.
# - Debian's triage (P2-D08, ADR 0022; owner decisions T1 to T8 on #134): FindingTriage for the page's findings, in
#   a fixed number of queries. The tab shows it under the advisory on open and reopened rows, with the "Debian: no
#   security update planned" chip (debian=no_dsa, open and reopened findings, counted within that state) and a
#   notice when the host release's triage is stale; the package page shows it on every row. It never changes a
#   finding's state, severity, the filters, or any count.
class HostVulnerabilitiesController < ApplicationController
  include HostTab

  STATES = %w[open resolved all].freeze
  FIXES = %w[available none].freeze
  QUERY_MAX = 100

  reads_from_replica only: %i[show package] # a caught-up replica when one is configured (#198)
  before_action :load_host_tab

  def show
    load_evaluation
    findings = VulnerabilityFinding.with_details.where(host_id: @host.id)
    # Counted on the findings alone, in one query: the details' joins add no rows (#254). The fix flag is NULL on
    # resolved findings, true or false on active ones, so the same query gives the fix chips' counts (#256).
    by_state = VulnerabilityFinding.where(host_id: @host.id).group(:state, :fixable).count
    count = ->(states, fixable = :any) { by_state.sum { |(state, flag), n| states.include?(state) && (fixable == :any || flag == fixable) ? n : 0 } }
    @state_counts = { "open" => count.(%w[open reopened]), "resolved" => count.(%w[resolved]) }
    @state_counts["all"] = @state_counts.values.sum
    @fix_counts = { "available" => count.(%w[open reopened], true), "none" => count.(%w[open reopened], false) }
    @state = STATES.include?(params[:state]) ? params[:state] : "open"
    @severity = Advisory::SEVERITIES.include?(params[:severity]) ? params[:severity] : nil
    @query = params[:q].to_s.strip.first(QUERY_MAX)
    # The chip narrows the open and reopened list, the rows that show Debian's triage (T3, T5).
    @debian = params[:debian] == "no_dsa" && @state == "open" ? "no_dsa" : nil
    # The fix filter is offered on the open and reopened list only (#252 question 7).
    @fix = FIXES.include?(params[:fix]) && @state == "open" ? params[:fix] : nil
    load_triage_context
    scope = filtered(findings)
    if @state == "open"
      # The chip counts every open and reopened finding Debian plans no security update for, whatever the severity and
      # text filters (T3), in one SQL count (review of #253, S6).
      @no_dsa_count = FindingTriage.no_dsa(findings.active.joins(:advisory), release: @triage_release, status: @triage_status).count
      scope = FindingTriage.no_dsa(scope, release: @triage_release, status: @triage_status) if @debian
      scope = scope.where(fixable: @fix == "available") if @fix
    end
    @open_groups = (groups(scope.where(state: %w[open reopened]), :open) unless @state == "resolved")
    @resolved_groups = (groups(scope.where(state: "resolved"), :resolved) unless @state == "open")
    # Debian's triage for the open and reopened rows on the page (T5); none on the resolved list.
    @triage = @open_groups && FindingTriage.load(@open_groups.groups.flat_map(&:findings))
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
  def sorted(findings) = findings.sort_by { |f| [ Advisory::SEVERITIES.index(f.advisory.severity), f.first_seen_at, f.advisory.advisory_id ] }

  # One section's page of package groups, each with its own cursor (after and before for the open section,
  # resolved_after and resolved_before for the resolved one). The open section ranks the biggest offenders first; the
  # resolved one keeps worst severity, then first seen (review of #253, S3).
  def groups(scope, section)
    prefix = section == :resolved ? "resolved_" : ""
    rank = section == :resolved ? :severity : :offenders
    HostFindingGroups.new(scope, rank:, after: HostFindingGroups.cursor(params[:"#{prefix}after"], rank), before: HostFindingGroups.cursor(params[:"#{prefix}before"], rank))
  end
end
