# Per-request context. RequestContext sets request_id so audit entries and log lines can be traced to a request,
# operator is the signed-in operator on dashboard requests, and host_id and report_id are set by the agent API
# once the credential and the report are known; the log shows them (StructuredLogFormatter).
class Current < ActiveSupport::CurrentAttributes
  attribute :request_id, :operator, :host_id, :report_id
end
