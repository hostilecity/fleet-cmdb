# The exposure tier, points, work items, and run badge as the fleet list, the host summary tiles, and the host tab show
# them (VT-SCORES #262, VT-D06; mockups fleet.html, tiles.html, states.html), with the honesty rules of the epic's VT-M5:
#
# - A host that is not evaluated, or not triaged yet, shows that in words, never a tier, 0 points, or "Nothing to
#   install". So does a host whose package report is older than the badge setting when its count is 0 ("Not known"):
#   a stale host never shows 0 points or "Nothing to install"; a count above 0 is shown with its date.
# - A stale or never-imported KEV source qualifies the tier ("not checked against KEV"); it never lowers it.
# - A run badge is withheld, saying why, when the host is stale or the advisory data is; its words are exactly its
#   claim ("No fixable critical for 12 days", "12-day run · 1 fixable critical, 4 days left").
# - Words and shapes (the tier's bars, the badge's mark), never colour alone.
module ExposureHelper
  # The fleet list's caption, naming its sort.
  def fleet_caption(fleet)
    return "Hosts, highest exposure first: by tier, then points" if fleet.sort == "exposure"
    return "Hosts, most work first" if fleet.sort == "work"

    "Hosts, #{{ 'last_seen' => 'last seen', 'cis' => 'CIS pass rate', 'vulns' => 'open vulnerabilities' }.fetch(fleet.sort, fleet.sort)} #{fleet.aria_sort(fleet.sort)}"
  end

  def tier_label(tier) = tag.span(VulnerabilityExposure.tier_name(tier), class: "tier t#{tier}")

  # "4 upgrades and a reboot", "22 upgrades, a new kernel, a reboot", "a reboot".
  def work_words(scores)
    parts = []
    parts << pluralize(number_with_delimiter(scores.work_upgrades), "upgrade") if scores.work_upgrades.positive?
    parts << "a new kernel" if scores.work_kernel_install
    parts << "a reboot" if scores.work_reboot
    parts.to_sentence(words_connector: ", ", two_words_connector: " and ", last_word_connector: ", ")
  end

  # "9 findings need attention", "1 finding needs attention", "0 need attention".
  def attention_words(count)
    return "0 need attention" if count.zero?

    "#{pluralize(number_with_delimiter(count), 'finding')} #{count == 1 ? 'needs' : 'need'} attention"
  end

  # Whether the host's package report is older than the badge setting (VT-M5 rule 2).
  def scores_stale?(scores, badges, now: Time.current)
    received = scores.packages_received_at
    received.nil? || received < now - badges[:report_max_age]
  end

  # "as of the package report 2 days ago" when the package report is overdue (ReportSchedule), else nil.
  def scores_as_of(scores, package_interval, now: Time.current)
    received = scores.packages_received_at
    return nil unless received && now - received > ReportSchedule::OVERDUE_INTERVALS * package_interval

    "as of the package report #{seen_ago(received)}"
  end

  # The fleet list's Exposure cell: tier, points, how many findings need attention.
  def fleet_exposure_cell(host, row, kev:, badges:, package_interval:)
    return tag.span("Not tracked", class: "muted") unless row
    return tag.span(safe_join([ "Not evaluated", tag.span(": #{vuln_reason_line(row).downcase_first}", class: "visually-hidden") ]), class: "not-eval") unless row.vulns_evaluated?

    scores = row.scores
    return tag.span("Not triaged yet", class: "not-eval") unless scores.scored?
    return not_known(scores) if scores.exposure_points.zero? && scores_stale?(scores, badges)

    detail = [ "#{pluralize(number_with_delimiter(scores.exposure_points), 'point')} · #{attention_words(scores.vuln_attention)}",
               VulnerabilityExposure.kev_qualifier(kev), scores_as_of(scores, package_interval) ].compact.join(" · ")
    safe_join([ link_to(tier_label(scores.exposure_tier), vulnerabilities_host_path(host, anchor: "score")), tag.span(detail, class: "rate-detail") ])
  end

  # The fleet list's Work cell: work items and what they are, or "Nothing to install" with the run badge.
  def fleet_work_cell(host, row, badges:, package_interval:, advisories_stale:)
    return tag.span("Not tracked", class: "muted") unless row
    return tag.span("Not known", class: "not-eval") unless row.vulns_evaluated?

    scores = row.scores
    return tag.span("Not counted yet", class: "not-eval") unless scores.scored?
    return not_known(scores) if scores.work_items.zero? && scores_stale?(scores, badges)

    as_of = scores_as_of(scores, package_interval)
    if scores.work_items.zero?
      lines = [ ("#{attention_words(scores.vuln_attention)}, no fix yet" if scores.vuln_attention.positive?), as_of ].compact
      return safe_join([ tag.span("Nothing to install", class: "none-open"), *lines.map { |line| tag.span(line, class: "rate-detail") },
                         run_badge(scores, badges:, advisories_stale:) ].compact)
    end

    safe_join([ link_to(pluralize(number_with_delimiter(scores.work_items), "work item"), vulnerabilities_host_path(host, anchor: "work")),
                tag.span([ work_words(scores), as_of ].compact.join(", "), class: "rate-detail") ])
  end

  # The run badge, or why it is withheld (withheld: true to say so; the fleet list leaves it out), or nil when the host
  # has no run.
  def run_badge(scores, badges:, advisories_stale:, withheld: false, now: Time.current)
    return nil unless scores.scored?

    reason = VulnerabilityExposure.withheld(received: scores.packages_received_at, advisories_stale:, now:, max_age: badges[:report_max_age])
    return (run_withheld(reason, scores) if withheld) if reason

    run = VulnerabilityExposure.run(scores, now:, grace: badges[:run_grace])
    return nil unless run

    days = run.days(now)
    if run.grace?
      left = (run.left / 1.day).ceil
      tag.span(safe_join([ "#{days}-day run", tag.span("#{pluralize(run.open, 'fixable critical')}, #{pluralize(left, 'day')} left", class: "scope") ], " · "),
               class: "honest grace", id: "run_badge")
    else
      tag.span(safe_join([ "No fixable critical", tag.span(days.zero? ? "for less than a day" : "for #{pluralize(days, 'day')}", class: "scope") ], " "),
               class: "honest streak", id: "run_badge")
    end
  end

  RUN_WITHHELD = { no_report: "no package report yet", advisories_stale: "the advisory data is out of date" }.freeze

  def run_withheld(reason, scores)
    why = reason == :report_old ? "last package report #{seen_ago(scores.packages_received_at)}" : RUN_WITHHELD.fetch(reason)
    tag.span(safe_join([ "Run withheld", tag.span(why, class: "scope") ], ": "), class: "honest withheld", id: "run_badge")
  end

  # The host summary tiles (mockup tiles.html): [big, detail] of Vulnerability exposure for a scored host.
  def exposure_tile_parts(scores, kev:, badges:, now: Time.current)
    stale = scores_stale?(scores, badges, now:)
    return [ tag.span("Not known", class: "not-eval"), "Last package report #{seen_ago(scores.packages_received_at)}" ] if stale && scores.exposure_points.zero?

    detail = [ pluralize(number_with_delimiter(scores.exposure_points), "point"),
               ("#{number_with_delimiter(scores.vuln_kev_advisories)} known exploited" if scores.vuln_kev_advisories.positive?),
               attention_words(scores.vuln_attention), VulnerabilityExposure.kev_qualifier(kev),
               ("as of the package report #{seen_ago(scores.packages_received_at)}" if stale) ].compact.join(" · ")
    [ tier_label(scores.exposure_tier), detail ]
  end

  # [big, detail] of Work remaining for a scored host: work items, what they are and the findings they clear, and the
  # progress of the last 30 days (withheld when the package report is old, VT-M5 rule 2).
  def work_tile_parts(scores, done:, badges:, now: Time.current)
    stale = scores_stale?(scores, badges, now:)
    return [ tag.span("Not known", class: "not-eval"), "Last package report #{seen_ago(scores.packages_received_at)}" ] if stale && scores.work_items.zero?

    items = scores.work_items
    big = safe_join([ number_with_delimiter(items), " ", tag.small(items == 1 ? "work item" : "work items") ])
    what = if items.zero?
      [ "Nothing to install", ("#{attention_words(scores.vuln_attention)}, no fix yet" if scores.vuln_attention.positive?) ].compact.join(" · ")
    else
      "#{work_words(scores)} · clears #{pluralize(number_with_delimiter(scores.vuln_fix), 'finding')}"
    end
    progress = if stale then "progress withheld: last package report #{seen_ago(scores.packages_received_at)}"
    elsif (total = done + items).zero? then nil
    else safe_join([ tag.meter("#{done} of #{total}", min: 0, max: total, value: done), " #{done} of #{total} done in 30 days" ])
    end
    [ big, safe_join([ what, progress ].compact, tag.br) ]
  end

  private

  def not_known(scores)
    safe_join([ tag.span("Not known", class: "not-eval"), tag.span("last package report #{seen_ago(scores.packages_received_at)}", class: "rate-detail") ])
  end
end
