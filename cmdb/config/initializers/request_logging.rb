# One structured line per request with its duration (NFR-4, P1-S11), next to the request id, host id, and report
# id that StructuredLogFormatter adds. Only the route (controller and action), method, status, and time are
# logged: never the query string, headers, or body. Active when config.x.logging.structured is set (production).
ActiveSupport::Notifications.subscribe("process_action.action_controller") do |event|
  next unless Rails.configuration.x.logging.structured

  payload = event.payload
  StructuredLogFormatter.with_fields(
    event: "request", method: payload[:method], controller: payload[:controller], action: payload[:action],
    status: payload[:status] || 500, duration_ms: event.duration.round(1)
  ) { Rails.logger.info("request completed") }
end
