# Locks an agent's host row for a write and re-checks, under that lock, what authentication saw: the
# credential is still active, the host is not retired, and the host is active (review of #50). Revocation,
# retirement, and re-enrollment change the host under the same lock, so the check is consistent.
# Used by every agent write (heartbeats, inventory reports). Must run inside a transaction.
module AgentHostLock
  # Why a write was refused; Api::V1::AuthenticatedController maps the reason to the documented error.
  class Refused < StandardError
    attr_reader :reason

    def initialize(reason)
      @reason = reason
      super("agent write refused: #{reason}")
    end
  end

  module_function

  def lock!(host_id:, credential_id:)
    host = Host.lock.find(host_id)
    raise Refused.new(:unauthorized) if host.retired? || !AgentCredential.active.exists?(id: credential_id, host_id:)
    raise Refused.new(:reenrollment_required) if host.enrollment_state == "pending"
    raise Refused.new(:host_not_active) unless host.enrollment_state == "active"

    host
  end
end
