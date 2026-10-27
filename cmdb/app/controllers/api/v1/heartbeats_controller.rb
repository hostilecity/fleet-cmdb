module Api
  module V1
    # POST /api/v1/heartbeat (FR-1.2, P1-S07). Updates last_seen_at from the server clock and the agent
    # version; the agent's reported time is stored separately and never used for liveness. A host that was
    # not online becomes online immediately, with a status history row. No audit entries and no credential
    # last-use write: a steady-state heartbeat is exactly one UPDATE. The host and credential are re-checked
    # under the host row lock, so a revocation or re-enrollment that lands mid-request is still refused.
    class HeartbeatsController < AuthenticatedController
      self.max_body_bytes = 4.kilobytes
      self.records_credential_use = false

      before_action :require_active_host!
      validates_body_with "heartbeat.request"
      atomic :create

      REFUSALS = {
        unauthorized: AgentApi::Unauthorized,
        reenrollment_required: AgentApi::ReenrollmentRequired,
        host_not_active: AgentApi::HostNotActive
      }.freeze

      def create
        recorded_at = Liveness.record_heartbeat!(host_id: current_host.id, credential_id: current_credential.id,
                                                 agent_version: payload["agent_version"], agent_schema_version: payload["schema_version"],
                                                 agent_time: Time.iso8601(payload["agent_time"]))
        render json: { server_time: recorded_at.utc.iso8601, directives: [] }
      rescue Liveness::Refused => e
        raise REFUSALS.fetch(e.reason)
      end
    end
  end
end
