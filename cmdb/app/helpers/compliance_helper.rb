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

  # "Config 5 hours ago" and "No package report yet" on two lines, worded as on the host reports tile, or "Never" when
  # neither has arrived.
  def last_reports(row)
    return "Never" unless row.config_received_at || row.packages_received_at

    safe_join([ report_age("config", row.config_received_at), report_age("packages", row.packages_received_at) ], tag.br)
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

  # The fleet compliance line of bucket totals (VT-SCORES #262, VT-D06; mockup tiles.html, "On the Compliance page"):
  # "412 fix available (61 work items) · 47 need attention · 11,280 low risk · 23,173 ignorable", each count a link
  # (link: bucket => path), the current filter marked. Findings, so they add up to the open count.
  BUCKET_WORDS = { "fix" => "fix available", "attention" => "need attention", "low_risk" => "low risk", "ignorable" => "ignorable" }.freeze
  def bucket_totals_line(totals, link, current: nil)
    parts = FleetCompliance::BUCKETS.keys.map do |bucket|
      words = "#{number_with_delimiter(totals.buckets[bucket])} #{BUCKET_WORDS.fetch(bucket)}"
      words = "#{totals.buckets[bucket] == 1 ? '1 needs' : "#{number_with_delimiter(totals.buckets[bucket])} need"} attention" if bucket == "attention"
      item = link_to(words, link.call(bucket), "aria-current": (current == bucket ? "true" : nil))
      bucket == "fix" ? safe_join([ item, " (#{pluralize(number_with_delimiter(totals.work_items), 'work item')})" ]) : item
    end
    safe_join([ safe_join(parts, " · "), " on #{totals.vulns_evaluated} of #{pluralize(totals.hosts, 'host')} evaluated." ])
  end

  # A host's open findings in Fix available and Needs attention on the Compliance page, linking to its tab's sections:
  # "12 fix available · 3 need attention". nil when nothing is open, or when the host is not evaluated now (its kept
  # findings are counted in the severity columns, not here).
  def bucket_detail(host, row)
    return nil unless row.vulns_evaluated? && row.vulns_open.positive?

    parts = { "fix" => "#{row.buckets['fix']} fix available", "attention" => attention_words(row.buckets["attention"]) }.map do |bucket, words|
      row.buckets[bucket].positive? ? link_to(words, vulnerabilities_host_path(host, bucket:, anchor: bucket == "fix" ? "fix" : "attn")) : words
    end
    tag.span(safe_join(parts, " · "), class: "rate-detail fix-detail")
  end
end
