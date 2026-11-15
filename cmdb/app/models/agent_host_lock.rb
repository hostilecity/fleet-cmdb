# Locks an agent's host row for a write and re-checks, under that lock, what authentication saw: the
# credential is still active, the host is not retired, and the host is active (review of #50). Revocation,
# retirement, and re-enrollment change the host under the same lock, so the check is consistent.
# Used by every agent write (heartbeats, inventory reports). Must run inside a transaction.
#
# One statement (#189): the host row FOR UPDATE, joined to the credential row FOR SHARE. Rows are locked in the
# order the clauses name them, host first, then credential, the order revocation takes them (Host#transition!).
# Locking the credential matters: when a revocation holds the host and this waits, PostgreSQL re-reads only the
# locked rows of a join once the lock is granted, so the credential's state is the committed one, not the one seen
# before the wait.
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
    host = Host.joins(:agent_credentials).where(id: host_id, agent_credentials: { id: credential_id, state: "active" })
               .lock("FOR UPDATE OF hosts FOR SHARE OF agent_credentials").take
    raise Refused.new(:unauthorized) if host.nil? || host.retired?
    raise Refused.new(:reenrollment_required) if host.enrollment_state == "pending"
    raise Refused.new(:host_not_active) unless host.enrollment_state == "active"

    host
  end
end
