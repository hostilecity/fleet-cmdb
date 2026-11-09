# Per-request context. RequestContext sets request_id so audit entries and log lines can be traced to a request,
# operator and operator_session are the signed-in operator and their session on dashboard requests, and host_id
# and report_id are set by the agent API once the credential and the report are known; the log shows them
# (StructuredLogFormatter).
class Current < ActiveSupport::CurrentAttributes
  attribute :request_id, :operator, :operator_session, :host_id, :report_id
end
