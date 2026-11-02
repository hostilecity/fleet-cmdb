require "json"
require "logger"

# One JSON object per log line (NFR-4, P1-S11): timestamp, level, message, and, when known, the request id,
# host id, and report id of the request or job being served, plus any fields a caller adds with .with_fields
# (the request line adds the duration). A report is traced by searching the log for its request_id or
# report_id. Messages are JSON-encoded, so a newline or control character in a value a VM sent cannot forge a
# second log line.
#
# Never log credentials: the fields here are identifiers only, and Rails filters request parameters
# (config/initializers/filter_parameter_logging.rb). Lives outside the autoloaded lib/ because production.rb
# needs it before the application loads.
class StructuredLogFormatter < Logger::Formatter
  FIELDS_KEY = :structured_log_fields
  MESSAGE_LIMIT = 8_000

  # Adds fields to every line logged inside the block, on this thread.
  def self.with_fields(**fields)
    previous = Thread.current[FIELDS_KEY]
    Thread.current[FIELDS_KEY] = (previous || {}).merge(fields)
    yield
  ensure
    Thread.current[FIELDS_KEY] = previous
  end

  def call(severity, time, _progname, message)
    entry = { time: time.utc.iso8601(3), level: severity, message: text(message) }
    entry.merge!(context)
    entry.merge!(Thread.current[FIELDS_KEY] || {})
    "#{JSON.generate(entry.compact)}\n"
  end

  private

  def context
    { request_id: Current.request_id, host_id: Current.host_id, report_id: Current.report_id }
  end

  def text(message)
    string = message.is_a?(String) ? message : (message.is_a?(Exception) ? "#{message.class}: #{message.message}" : message.inspect)
    string.scrub.truncate(MESSAGE_LIMIT)
  end
end
