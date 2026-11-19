# Display helpers for the Vulnerabilities tab and one package's findings (P2-D04, approved mockups host-vulns.html,
# host-vuln-package.html, states-packages-vulns.html). Advisory text comes from an outside source and package data
# from an agent: both pass through Rails' escaping. A link to the source advisory is drawn only for an http or https
# URL with a host, and always opens with rel="noopener noreferrer".
module HostVulnerabilitiesHelper
  RESOLUTIONS = {
    "fixed" => "Fixed: the installed version is outside the affected ranges", "removed" => "Removed: package no longer installed",
    "withdrawn" => "Withdrawn: the advisory was withdrawn by its source", "not_affected" => "Not affected: the advisory no longer names this package"
  }.freeze
  # What each reason for not evaluating means for the operator, after the server's own sentence (HostContext).
  NEXT_STEPS = {
    "no_inventory" => "It is evaluated as soon as the agent sends its first inventory and package reports.",
    "unmapped_distribution" => "Adding a distribution needs a new decision; until then its packages are listed but not matched.",
    "no_package_report" => :request_packages,
    "unsupported_package_manager" => "Packages and vulnerabilities cannot be shown for this host.",
    "unreadable_packages" => "Its findings are matched again after the next package report that can be read; request one on the Packages tab.",
    "no_advisory_data" => :failed_jobs
  }.freeze

  def finding_state_lamp(finding)
    case finding.state
    when "resolved" then tag.span("Resolved", class: "lamp online")
    when "reopened" then tag.span("Reopened", class: "lamp fail")
    else tag.span("Open", class: "lamp fail")
    end
  end

  # The advisory id, linked to the source advisory when it has a web address, with its summary.
  def advisory_cell(advisory)
    url = web_url(advisory.reference_url)
    id = url ? link_to(advisory.advisory_id, url, rel: "noopener noreferrer", target: "_blank") : tag.span(advisory.advisory_id, class: "mono")
    safe_join([ id, (tag.span("No link recorded", class: "state-note") unless url), (tag.span(advisory.summary, class: "state-note") if advisory.summary.present?),
                (tag.span("The source gave no severity.", class: "state-note") if advisory.severity == "unknown") ].compact)
  end

  # The URL when it is http or https with a host and no whitespace or control characters; nil otherwise.
  def web_url(url)
    return nil unless url.is_a?(String) && !url.match?(/[[:space:][:cntrl:]]/)

    uri = URI.parse(url)
    url if %w[http https].include?(uri.scheme&.downcase) && uri.host.present?
  rescue URI::InvalidURIError
    nil
  end

  def fixed_in(finding)
    finding.fixed_version ? safe_join([ "Fixed in ", tag.span(finding.fixed_version, class: "mono") ]) : tag.span("No fix available", class: "unavailable")
  end

  # A package row's fix count (HostFindingGroups::Group): how many of its findings have a known fixed version for the
  # host's release, never "N findings" alone (owner request). Whether that version is in the host's repositories yet
  # is not known to the server.
  def fixable_count(group)
    fixable, total = group.fixable, group.total
    if fixable.zero? then tag.span(total == 1 ? "No fix available" : "No fix for any of #{total}", class: "unavailable")
    elsif fixable == total then total == 1 ? "Fix available" : "Fix for all #{total}"
    else "Fix for #{fixable} of #{total}"
    end
  end

  # How a resolved package row's findings resolved, in the order RESOLUTIONS lists them: "2 fixed, 1 removed".
  def group_resolutions(group) = group.resolutions.sort_by { |resolution, _| RESOLUTIONS.keys.index(resolution) }.map { |resolution, count| "#{count} #{resolution.tr('_', ' ')}" }.join(", ")

  # "2 high, 18 medium" for a package row, worst first.
  def finding_severity_breakdown(group) = severity_counts(group.counts.select { |_, count| count.positive? })

  # "45 open, 2 reopened" or "3 resolved" for a package row.
  def group_states(group) = group.states.sort_by { |state, _| VulnerabilityFinding::STATES.index(state) }.map { |state, count| "#{count} #{state}" }.join(", ")

  # "2026-11-03 06:12 UTC → —", "... → 2026-11-05 18:30 UTC", or with a resolution and a reopening.
  def finding_dates(finding)
    after = case finding.state
    when "resolved" then utc(finding.resolved_at)
    when "reopened" then tag.span("Resolved #{utc(finding.resolved_at)}, reopened #{utc(finding.reopened_at)}", class: "muted")
    else tag.span("—", class: "muted")
    end
    safe_join([ utc(finding.first_seen_at), " → ", after ])
  end

  # When the finding was first seen, last resolved, and last reopened, oldest first. A finding keeps only its latest
  # resolution and reopening, so earlier rounds are not listed.
  def finding_history(finding)
    events = [ [ finding.first_seen_at, "first seen" ] ]
    events << [ finding.resolved_at, finding.resolution ? "resolved: #{RESOLUTIONS.fetch(finding.resolution).downcase_first}" : "resolved" ] if finding.resolved_at
    events << [ finding.reopened_at, "reopened" ] if finding.reopened_at
    tag.ul(safe_join(events.sort_by(&:first).map { |at, what| tag.li("#{utc(at)} #{what}") }), class: "change-list")
  end

  # The step after a not-evaluated reason, as text or a link.
  def not_evaluated_next_step(host, reason)
    case NEXT_STEPS[reason]
    when :request_packages then safe_join([ link_to("Request a package report", packages_host_path(host, anchor: "request")), " or wait for the next scheduled one." ])
    when :failed_jobs then safe_join([ link_to("Check the failed jobs", failed_jobs_path), ": the first refresh may have failed or not run yet." ])
    else NEXT_STEPS.fetch(reason, "")
    end
  end
end
