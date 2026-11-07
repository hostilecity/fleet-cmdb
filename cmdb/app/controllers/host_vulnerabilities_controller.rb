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
    shown = filtered(findings).to_a
    @open_groups = groups(shown.select { |f| f.state != "resolved" })
    @resolved_groups = groups(shown.select { |f| f.state == "resolved" })
    @advisory_count = AdvisoryPackage.where(ecosystem: @evaluation.ecosystem).distinct.count(:advisory_id) if @evaluation && !@evaluation.not_evaluated?
  end

  def package
    @package = params[:package].to_s
    @installed = HostPackage.where(host_id: @host.id, name: @package).order(:architecture).to_a
    @findings = sorted(VulnerabilityFinding.where(host_id: @host.id, package: @package).includes(:advisory).to_a)
    raise ActiveRecord::RecordNotFound, "the host has no such package and no finding for it" if @installed.empty? && @findings.empty?

    @set = HostPackageSet.find_by(host_id: @host.id)
    @ecosystem = @findings.first&.ecosystem || HostVulnerabilityEvaluation.where(host_id: @host.id).pick(:ecosystem)
    sources = (@installed.map(&:source) + @findings.map(&:source)).compact.uniq
    @siblings = VulnerabilityFinding.where(host_id: @host.id, source: sources).where.not(package: @package).distinct.order(:package).pluck(:package)
  end

  private

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
