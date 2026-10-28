module ApplicationHelper
  LAMP_CLASSES = { "online" => "online", "stale" => "stale", "offline" => "offline", "awaiting" => "awaiting", "pending" => "pending", "revoked" => "revoked" }.freeze

  # A status lamp with its word: colour is never the only signal.
  def status_lamp(host)
    key = FleetList.status_of(host)
    tag.span(FleetList::STATUSES.fetch(key, key.humanize), class: [ "lamp", LAMP_CLASSES[key] ])
  end

  # "28 seconds ago", or "Never".
  def seen_ago(time)
    time ? "#{time_ago_in_words(time, include_seconds: true)} ago" : "Never"
  end

  def utc(time)
    time&.utc&.strftime("%Y-%m-%d %H:%M UTC")
  end

  def human_bytes(bytes) = ByteSize.format(bytes)

  # 90061 -> "1 day, 1 hour".
  def human_duration(seconds)
    return nil if seconds.nil?

    parts = ActiveSupport::Duration.build(seconds).parts.slice(:years, :months, :weeks, :days, :hours, :minutes).reject { |_, v| v.zero? }.first(2)
    parts.empty? ? "under a minute" : parts.map { |unit, value| pluralize(value, unit.to_s.singularize) }.join(", ")
  end

  # A bar that fills to the free or available share (mockups: P1-D01).
  def share_meter(part, whole, title)
    return "" unless part && whole&.positive?

    # Width classes in 5% steps rather than an inline style, so the CSP can forbid inline styles.
    step = ((100.0 * part / whole).clamp(0, 100) / 5).round * 5
    tag.span(tag.span(class: "w-#{step}"), class: "meter", title:, "aria-hidden": "true")
  end
end
