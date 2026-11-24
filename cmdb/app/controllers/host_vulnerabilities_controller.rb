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
# - Triage (VT-HOST-TAB #260, FR-2.6; approved mockup vuln-triage/host-vulns.html): the open list is drawn by
#   bucket (HostTriageSections): a strip of the four bucket counts, which always add up to the open count (counted in
#   the state counts' one grouped query, so over the whole open list whatever the filters), work remaining and 30-day
#   progress in work items (HostVulnerabilityWork), and one section per bucket. A signal filter (?signal= kev, epss,
#   network) combines with the others; ?bucket= keeps one section and ?rule= opens one Low risk or Ignorable rule's
#   package rows. Open findings with no bucket yet (a host the upgrade's background re-triage has not reached) are
#   "not triaged yet", never 0 in every bucket. The bucket strip replaces VT-FIXABLE's fix chips (#256), whose
#   "Fix available" meant a different thing than the bucket.
# - Debian's triage (P2-D08, ADR 0022; owner decisions T1 to T8 on #134): FindingTriage for the page's findings, in
#   a fixed number of queries. The tab shows it under the advisory on open and reopened rows, with the "Debian: no
#   security update planned" chip (debian=no_dsa, open and reopened findings, counted within that state) and a
#   notice when the host release's triage is stale; the package page shows it on every row. It never changes a
#   finding's state, severity, the filters, or any count.
class HostVulnerabilitiesController < ApplicationController
  include HostTab

  STATES = %w[open resolved all].freeze
  # The signal filter (VT-HOST-TAB #260): known exploited (the finding's stored KEV flag), EPSS in the high band (any
  # CVE of the advisory), and network with no login and no user action (the advisory's CVSS vector).
  SIGNALS = %w[kev epss network].freeze
  # The advisory's CVE ids, as VulnerabilityTriage::Base reads them: its id without "DEBIAN-", and its aliases.
  EPSS_HIGH_SQL = <<~SQL.squish.freeze
    EXISTS (SELECT 1 FROM epss_scores e WHERE e.band = 'high'
            AND e.cve_id = ANY (array_append(advisories.aliases, regexp_replace(advisories.advisory_id, '^DEBIAN-', '')::varchar)))
  SQL
  QUERY_MAX = 100

  reads_from_replica only: %i[show package] # a caught-up replica when one is configured (#198)
  before_action :load_host_tab

  def show
    load_evaluation
    findings = VulnerabilityFinding.with_details.where(host_id: @host.id)
    # Counted on the findings alone, in one query: the details' joins add no rows (#254). Grouped by the triage bucket
    # too (VT-HOST-TAB #260), so the four buckets add up to the open count in the same snapshot; a NULL bucket on an
    # open finding is one the upgrade's background re-triage has not reached yet (#277 item 15).
    # And by the stored fix flag (VT-FIXABLE #256), for ?fix=available: the count the Compliance page and the fleet list
    # link here with.
    by_state = VulnerabilityFinding.where(host_id: @host.id).group(:state, :bucket, Arel.sql(VulnerabilityFinding::FIX_SQL)).count
    count = ->(states) { by_state.sum { |(state, _, _), n| states.include?(state) ? n : 0 } }
    @state_counts = { "open" => count.(%w[open reopened]), "resolved" => count.(%w[resolved]) }
    @state_counts["all"] = @state_counts.values.sum
    @bucket_counts = (VulnerabilityTriage::BUCKETS.keys + [ "untriaged" ]).index_with(0)
    by_state.each { |(state, bucket, _), n| @bucket_counts[VulnerabilityTriage.bucket_for(bucket) || "untriaged"] += n unless state == "resolved" }
    @fixable_count = by_state.sum { |(state, _, fixable), n| state != "resolved" && fixable ? n : 0 }
    @state = STATES.include?(params[:state]) ? params[:state] : "open"
    @severity = Advisory::SEVERITIES.include?(params[:severity]) ? params[:severity] : nil
    @query = params[:q].to_s.strip.first(QUERY_MAX)
    @signal = SIGNALS.include?(params[:signal]) && @state != "resolved" ? params[:signal] : nil
    @bucket = HostTriageSections::BUCKETS.include?(params[:bucket]) && @state != "resolved" ? params[:bucket] : nil
    @rule = HostTriageSections.rule_param(params[:rule]) if @state != "resolved"
    # The chip narrows the open and reopened list, the rows that show Debian's triage (T3, T5).
    @debian = params[:debian] == "no_dsa" && @state == "open" ? "no_dsa" : nil
    # The Compliance page's and the fleet list's "N with a fix" land here (review of #281, S1): the open findings whose
    # advisory data names a fix, the same stored flag they count, so the numbers agree. No chip: the bucket strip is
    # the tab's own "Fix available".
    @fix = params[:fix] == "available" && @state == "open" ? "available" : nil
    load_triage_context
    @signals = Signals::Freshness.statuses
    scope = filtered(findings)
    unless @state == "resolved"
      # The chip counts every open and reopened finding Debian plans no security update for, whatever the severity and
      # text filters (T3), in one SQL count (review of #253, S6).
      @no_dsa_count = FindingTriage.no_dsa(findings.active.joins(:advisory), release: @triage_release, status: @triage_status).count if @state == "open"
      scope = FindingTriage.no_dsa(scope, release: @triage_release, status: @triage_status) if @debian
      scope = with_signal(scope) if @signal
      if @fix
        scope = scope.with_fix
        # What the line says is shown: the other filters narrow it too (one count, with ?fix= only; re-check of #281, N1).
        @fix_shown = filtered_besides_fix? ? scope.where(state: %w[open reopened]).count : @fixable_count
      end
      cursors = HostTriageSections::CURSORS.to_h { |section| [ section, [ params[:"#{section}_after"], params[:"#{section}_before"] ] ] }
      # With no open finding triaged yet, only the not-triaged section is drawn: no bucket reads 0 for them (#277 item 15).
      untriaged_only = @bucket_counts["untriaged"].positive? && @bucket_counts["untriaged"] == @state_counts["open"]
      @sections = HostTriageSections.new(scope.where(state: %w[open reopened]), bucket: untriaged_only ? "untriaged" : @bucket, rule: @rule, cursors:,
                                                                                untriaged: @bucket_counts["untriaged"])
      @work = HostVulnerabilityWork.new(@host.id)
      @listeners = VulnerabilityTriage::HostFacts.listener_coverage(@host.id)
    end
    @resolved_groups = (groups(scope.where(state: "resolved"), :resolved) unless @state == "open")
    # Debian's triage for the open and reopened rows on the page (T5); none on the resolved list.
    @triage = @sections && FindingTriage.load(@sections.findings)
    @advisory_count = AdvisoryPackage.where(ecosystem: @evaluation.ecosystem).distinct.count(:advisory_id) if @evaluation && !@evaluation.not_evaluated?
    # Backports are matched against the release they are built from too (#274): the tab says which, and where that
    # release's data names nothing for one.
    @backports = HostBackports.new(@evaluation.ecosystem, @package_set&.package_set_id, host_id: @host.id) if @evaluation && !@evaluation.not_evaluated?
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

  def filtered_besides_fix? = @severity || @query.present? || @debian || @signal

  def with_signal(scope)
    case @signal
    when "kev" then scope.where(kev: true)
    when "epss" then scope.where(EPSS_HIGH_SQL)
    else scope.where(advisories: { cvss_av: "N", cvss_pr: "N", cvss_ui: "N" })
    end
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
