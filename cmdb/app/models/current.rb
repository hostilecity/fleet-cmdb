# Per-request context. ApplicationController sets request_id so audit entries can be traced to a request,
# and operator to the signed-in operator on dashboard requests.
class Current < ActiveSupport::CurrentAttributes
  attribute :request_id, :operator
end
