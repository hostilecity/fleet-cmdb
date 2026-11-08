# Display helpers for on-demand report requests (P2-S03): the Overview's three-way form and each tab's own request
# button (P2-D02, approved mockup report-requests.html, owner decisions Q6 and Q7).
module ReportRequestsHelper
  REPORT_TYPE_NAMES = { "config" => "config", "inventory" => "inventory", "packages" => "package" }.freeze
  # How long after a request ended its outcome stays beside the button.
  OUTCOME_SHOWN_FOR = ReportRequests::TTL

  # "config report", "config and package reports".
  def report_names(types)
    "#{types.map { |type| REPORT_TYPE_NAMES.fetch(type) }.to_sentence} #{types.one? ? 'report' : 'reports'}"
  end

  # Where a request stands, in words: waiting for a heartbeat, asked, answered, or expired.
  def report_request_status(request, now = Time.current)
    case request.display_state(now)
    when "satisfied" then "Received #{utc(request.satisfied_at)}"
    when "expired" then "Expired #{utc(request.expired_at || request.expires_at)}: no report arrived within #{ReportRequests::TTL.in_minutes.to_i} minutes"
    else
      request.sent_at ? "Agent asked #{utc(request.sent_at)}, waiting for the report" : "Waiting for the agent's next heartbeat"
    end
  end

  # "12:08:20 UTC" today, "2026-11-06 12:08:20 UTC" on another day.
  def utc_clock(time, now = Time.current)
    time.utc.strftime(time.utc.to_date == now.utc.to_date ? "%H:%M:%S UTC" : "%Y-%m-%d %H:%M:%S UTC")
  end

  # "Try again after 12:08:20 UTC." for a rate-limited type.
  def report_retry_text(availability) = "Try again after #{utc_clock(availability.retry_at)}."

  # The outcome of the type's newest request, when it ended recently enough to show beside the button: :answered,
  # :expired, or nil.
  def recent_outcome(availability, now = Time.current)
    request = availability.latest
    return nil unless request

    state = request.display_state(now)
    ended_at = { "satisfied" => request.satisfied_at, "expired" => request.expired_at || request.expires_at }[state]
    return nil unless ended_at && ended_at > now - OUTCOME_SHOWN_FOR

    state == "satisfied" ? :answered : :expired
  end

  # Data attributes that refresh the page when a rate limit ends, so the button comes back by itself (Q7).
  def refresh_when_available(availabilities, now = Time.current)
    retry_at = Array(availabilities).filter_map(&:retry_at).min
    return {} unless retry_at

    { controller: "refresh-after", refresh_after_seconds_value: (retry_at - now).ceil }
  end
end
