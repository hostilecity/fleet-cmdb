# How often the server expects each report type from an agent, and when one is late (owner decision on #255, for the
# host page's reports tile). The server knows only the intervals it sends agents: the operator's inventory interval
# (Setting.agent_intervals), or the agent's default. The config report interval is set in the agent's own config file
# and is not reported, so the server assumes the agent's default; package reports follow the config report interval.
module ReportSchedule
  # The agent's defaults, in seconds (agent/src/config.rs: INVENTORY_LIMITS and CONFIG_REPORT_LIMITS).
  DEFAULT_SECONDS = { "config" => 21_600, "packages" => 21_600, "inventory" => 900 }.freeze
  # A report is overdue once it is older than this many intervals ("about twice its interval").
  OVERDUE_INTERVALS = 2
  # A report type that has never arrived is missing once the host was first seen this many intervals ago. One interval
  # is what the Packages tab promises: "within 6 hours of enrolling". Until then it is awaited.
  GRACE_INTERVALS = 1

  module_function

  # { "config" => 21600, "packages" => 21600, "inventory" => 900 }, with the operator's inventory interval when set.
  # One small query, read fresh (not through SettingsCache, which is for the agent API), so a page drawn just after
  # the setting changed judges by the new interval and the page's query count stays the same on every render.
  def intervals
    inventory = Setting.agent_intervals[:inventory_seconds]
    inventory ? DEFAULT_SECONDS.merge("inventory" => inventory) : DEFAULT_SECONDS
  end

  # :on_schedule, :overdue, :missing, or :awaited, for a report type received at `received_at` (nil if never) on a
  # host first seen at `first_seen_at` (nil if never).
  def state(received_at:, interval:, first_seen_at:, now:)
    if received_at
      now - received_at > OVERDUE_INTERVALS * interval ? :overdue : :on_schedule
    else
      first_seen_at && now - first_seen_at > GRACE_INTERVALS * interval ? :missing : :awaited
    end
  end
end
