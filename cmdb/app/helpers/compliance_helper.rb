# Display helpers for the fleet compliance view and the fleet list's compliance panel and columns (P2-D05, approved mockups
# compliance.html and fleet.html). Three things look different on purpose: a grey 0 is a severity with nothing open on a
# host that has something open, "None open" is an evaluated host with nothing open, and "Not evaluated" with its reason is
# a host the server could not judge. The product says "CIS-aligned" and "passes N of M checks", never "compliant" (ADR 0010).
module ComplianceHelper
  # Why a host's vulnerabilities are not evaluated, in a short line (the host's Vulnerabilities tab says it in full).
  VULN_REASONS = {
    "no_inventory" => "No inventory yet, so the distribution is not known",
    "unmapped_distribution" => "Its distribution is not in the fleet profile",
    "no_package_report" => "No package report yet",
    "unsupported_package_manager" => "Its package manager is not supported",
    "unreadable_packages" => "Its package database could not be read",
    "no_advisory_data" => "No advisory data imported for %s"
  }.freeze

  def vuln_reason_line(row)
    return "Not matched against advisories yet" unless (line = VULN_REASONS[row.vuln_reason])

    format(line, row.vuln_ecosystem)
  end

  def cis_reason_line(row, rules_defined)
    return "No rules are defined" unless rules_defined
    return "No config report yet" unless row.config_report?

    "No check has a pass or fail result yet"
  end

  # "Not evaluated" and its reason, in one cell spanning the columns it stands for.
  def not_evaluated_cell(reason, colspan)
    tag.td(safe_join([ tag.span("Not evaluated", class: "not-eval"), tag.span(reason, class: "reason-line") ]), colspan:)
  end

  def none_open_cell(colspan) = tag.td(tag.span("None open", class: "none-open"), colspan:)

  # One severity's count: grey when zero, bold when critical or high and not zero.
  def sevcount_cell(count, severity)
    tag.td(count, class: [ "sevcount", ("zero" if count.zero?), ("hot" if count.positive? && severity.in?(%w[critical high])) ])
  end

  # The pass rate with its meter, and "passes 33 of 35 checks".
  def pass_rate_cell(row)
    tag.td(safe_join([ tag.span(safe_join([ pass_percent(row.pass_rate), share_meter(row.cis_passed, row.cis_counted, "Pass rate") ]), class: "rate"),
                       tag.span("passes #{row.cis_passed} of #{row.cis_counted} checks", class: "rate-detail") ]))
  end

  # "Config 5 hours ago" and "Packages never" on two lines, or "Never" when neither has arrived.
  def last_reports(row)
    return "Never" unless row.config_received_at || row.packages_received_at

    safe_join([ "Config #{seen_ago(row.config_received_at).downcase_first}", "Packages #{seen_ago(row.packages_received_at).downcase_first}" ], tag.br)
  end

  # "1 critical, 3 high" for the fleet list's summary panel.
  def critical_and_high(counts) = "#{counts['critical']} critical, #{counts['high']} high"

  # The worst severity with something open, when it is critical or high: "1 critical", "2 high", or nil.
  def worst_severe(counts)
    severity = %w[critical high].find { |s| counts[s].positive? }
    "#{counts[severity]} #{severity}" if severity
  end

  # The fleet list's CIS pass rate cell (owner decision Q8): a link to the host's results.
  def fleet_cis_cell(host, row, rules_defined)
    return tag.span("Not tracked", class: "muted") unless row
    return tag.span(safe_join([ "Not evaluated", tag.span(": #{cis_reason_line(row, rules_defined).downcase_first}", class: "visually-hidden") ]), class: "not-eval") unless row.cis_evaluated?

    detail = row.cis_failed.zero? ? tag.span("None failing", class: "none-open") : [ "#{row.cis_failed} failing", worst_severe(row.cis) ].compact.join(", ")
    safe_join([ link_to(pass_percent(row.pass_rate), config_host_path(host, anchor: "results")), tag.span(detail, class: "rate-detail") ])
  end

  # The fleet list's open vulnerabilities cell: a link to the host's Vulnerabilities tab.
  def fleet_vulns_cell(host, row)
    return tag.span("Not tracked", class: "muted") unless row
    return tag.span(safe_join([ "Not evaluated", tag.span(": #{vuln_reason_line(row).downcase_first}", class: "visually-hidden") ]), class: "not-eval") unless row.vulns_shown?
    return tag.span("None open", class: "none-open") if row.vulns_open.zero?

    safe_join([ link_to("#{row.vulns_open} open", vulnerabilities_host_path(host)), (tag.span(worst_severe(row.vulns), class: "rate-detail") if worst_severe(row.vulns)) ].compact)
  end
end
