module Api
  module V1
    # POST /api/v1/enroll: redeems a single-use enrollment token for the host's credential (DEC-04, P1-S05).
    # Unauthenticated apart from the token, with a stricter per-address rate limit.
    class EnrollmentsController < BaseController
      self.max_body_bytes = 4.kilobytes

      rate_limit to: AgentApi.config.enroll_rate_limit[:to], within: AgentApi.config.enroll_rate_limit[:within],
                 by: -> { request.remote_ip }, store: AgentApi.rate_limit_store, name: "enroll", scope: "agent_api",
                 with: -> { rate_limited!(AgentApi.config.enroll_rate_limit[:within]) }
      validates_body_with "enroll.request"

      def create
        credential = Enrollment::Redeem.call(token: payload["token"], machine_id: payload["machine_id"],
                                             agent_version: payload["agent_version"], schema_version: payload["schema_version"])
        render json: { credential:, server_time: Time.current.utc.iso8601 }, status: :created
      end
    end
  end
end
