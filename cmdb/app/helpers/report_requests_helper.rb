# Display helpers for on-demand report requests on the host page (P2-S03; the full configuration tab is P2-D02).
module ReportRequestsHelper
  REPORT_TYPE_NAMES = { "config" => "config", "inventory" => "inventory", "packages" => "package" }.freeze

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
end
