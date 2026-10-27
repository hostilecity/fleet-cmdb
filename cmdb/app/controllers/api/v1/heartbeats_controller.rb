module Api
  module V1
    # POST /api/v1/heartbeat (FR-1.2, P1-S07). Updates last_seen_at from the server clock and the agent
    # version; the agent's reported time is stored separately and never used for liveness. A host that was
    # not online becomes online immediately, with a status history row. No audit entries.
    class HeartbeatsController < AuthenticatedController
      self.max_body_bytes = 4.kilobytes

      before_action :require_active_host!
      validates_body_with "heartbeat.request"
      atomic :create

      def create
        now = Time.current
        Liveness.record_heartbeat!(current_host, agent_version: payload["agent_version"], agent_schema_version: payload["schema_version"],
                                   agent_time: Time.iso8601(payload["agent_time"]), now:)
        render json: { server_time: now.utc.iso8601, directives: [] }
      end
    end
  end
end
