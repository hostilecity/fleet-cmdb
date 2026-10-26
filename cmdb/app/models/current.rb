# Per-request context. ApplicationController sets request_id so audit entries can be traced to a request.
class Current < ActiveSupport::CurrentAttributes
  attribute :request_id
end
