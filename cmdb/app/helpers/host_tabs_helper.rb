# The host tab bar and summary tiles (P2-D02 to P2-D04, approved mockups, owner decision Q1): real links, so the
# current tab is aria-current, never a script-driven tab widget.
module HostTabsHelper
  TABS = { overview: "Overview", config: "Configuration", packages: "Packages", vulnerabilities: "Vulnerabilities", tasks: "Tasks" }.freeze

  def host_tab_path(host, tab, **params)
    case tab
    when :overview then host_path(host, **params)
    when :config then config_host_path(host, **params)
    when :packages then packages_host_path(host, **params)
    when :vulnerabilities then vulnerabilities_host_path(host, **params)
    when :tasks then tasks_host_path(host, **params)
    end
  end

  def host_tabs(host, summary, current:)
    tag.nav(class: "tabs", "aria-label": "Host sections") do
      safe_join(TABS.map do |tab, label|
        count = tab_count(summary, tab)
        link_to(safe_join([ label, (tag.span(count, class: "count") if count) ].compact, " "), host_tab_path(host, tab), "aria-current": (tab == current ? "page" : nil))
      end)
    end
  end

  # The count beside a tab's name: packages installed ("Unsupported" when unknown), findings to act on (Fix available
  # plus Needs attention; "Not evaluated" when the host is not, unless findings from an earlier evaluation are still
  # open), and tasks running or waiting.
  def tab_count(summary, tab)
    case tab
    when :packages
      set = summary.package_set
      return nil unless set
      return "Unsupported" if set.unsupported?
      return "Unreadable" unless set.known?

      number_with_delimiter(set.package_count)
    when :vulnerabilities
      # "N to act on": Fix available plus Needs attention (epic decision 17, VT-HOST-TAB); "N open" while any open
      # finding is not triaged yet, so no zero stands for findings with no bucket (#277 item 15).
      return "Not evaluated" unless summary.vulnerabilities_evaluated? || summary.open_findings.positive?

      act = summary.to_act_on
      act ? "#{number_with_delimiter(act)} to act on" : "#{number_with_delimiter(summary.open_findings)} open"
    when :tasks
      running = summary.open_tasks["running"].to_i
      waiting = summary.open_tasks.values_at("queued", "claimed").sum(&:to_i)
      if running.positive? then "#{running} running"
      elsif waiting.positive? then "#{waiting} waiting"
      end
    end
  end

  # "80.6%", from a pass rate between 0 and 1.
  def pass_percent(rate) = "#{number_with_precision(rate * 100, precision: 1, strip_insignificant_zeros: true)}%"

  # A tile: a link when it has somewhere to go.
  def glance_tile(label, big, detail, href: nil, id: nil)
    body = safe_join([ tag.span(label, class: "label"), tag.span(big, class: "big"), tag.span(detail, class: "detail") ])
    href ? link_to(body, href, id:) : tag.div(body, id:)
  end

  # "1 high, 2 medium, 1 unknown".
  def severity_counts(pairs) = pairs.map { |severity, count| "#{count} #{severity}" }.join(", ")

  # The reports tile's headline (owner decision on #255): "Missing packages" for a type that never arrived within its
  # grace period, "Config and packages overdue" for types older than about twice their interval (both, joined, when
  # both apply), "Waiting for packages" for a newly seen host's first reports, and "On schedule" otherwise.
  def reports_headline(summary)
    missing = summary.report_types(:missing)
    overdue = summary.report_types(:overdue)
    if missing.any? || overdue.any?
      words = [ ("missing #{missing.to_sentence}" if missing.any?), ("#{overdue.to_sentence} overdue" if overdue.any?) ].compact.join(", ")
      tag.span(words.upcase_first, class: "overdue")
    elsif (awaited = summary.report_types(:awaited)).any?
      tag.span("Waiting for #{awaited.to_sentence}", class: "not-eval")
    else
      tag.span("On schedule", class: "none-open")
    end
  end

  # The reports tile's detail, one line per type in a fixed order (as in the approved mockup, so a refresh never moves
  # them): "Config 3 hours ago", "No package report yet", and for an overdue type, as the advisory data notice words
  # staleness, "Packages about 14 hours ago, older than 12 hours".
  def reports_detail(summary)
    safe_join(HostSummary::REPORT_TYPES.map do |type|
      line = report_age(type, summary.received[type])
      next line unless summary.report_state(type) == :overdue

      "#{line}, older than #{human_duration(ReportSchedule::OVERDUE_INTERVALS * summary.intervals.fetch(type))}"
    end, tag.br)
  end
end
