# The host tab bar and summary tiles (P2-D02 to P2-D04, approved mockups, owner decision Q1): real links, so the
# current tab is aria-current, never a script-driven tab widget.
module HostTabsHelper
  TABS = { overview: "Overview", config: "Configuration", packages: "Packages", vulnerabilities: "Vulnerabilities" }.freeze

  def host_tab_path(host, tab, **params)
    case tab
    when :overview then host_path(host, **params)
    when :config then config_host_path(host, **params)
    when :packages then packages_host_path(host, **params)
    when :vulnerabilities then vulnerabilities_host_path(host, **params)
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

  # The count beside a tab's name: packages installed ("Unsupported" when unknown), open findings ("Not evaluated"
  # when the host is not, unless findings from an earlier evaluation are still open).
  def tab_count(summary, tab)
    case tab
    when :packages
      set = summary.package_set
      return nil unless set
      return "Unsupported" if set.unsupported?
      return "Unreadable" unless set.known?

      number_with_delimiter(set.package_count)
    when :vulnerabilities
      summary.vulnerabilities_evaluated? || summary.open_findings.positive? ? "#{number_with_delimiter(summary.open_findings)} open" : "Not evaluated"
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

  # "dpkg, set last changed 1 day ago" for the packages tile.
  def package_tile_detail(summary)
    set = summary.package_set
    return "No package report yet" if set.nil?
    return "Unsupported package manager" if set.unsupported?
    return "Package database could not be read" unless set.known?
    return "Last report could not be read, list is from the last one that could" if set.unreadable?

    [ set.manager, (" set last changed #{seen_ago(summary.packages_changed_at)}" if summary.packages_changed_at) ].compact.join(",")
  end
end
