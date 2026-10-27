module Api
  module V1
    # Base for every endpoint an agent calls with its credential (FR-S.1, FR-S.2, P1-S04).
    #
    # The host is always the one the credential belongs to (#current_host). Never look a host up from the
    # request: no endpoint takes a host identifier, so one host cannot read or write another's data (AC-1.6).
    # Missing, malformed, unknown, revoked, and retired-host credentials all get the same 401, and there is
    # no authentication cache, so revocation takes effect on the next request (AC-1.5).
    class AuthenticatedController < BaseController
      before_action :authenticate_agent!
      rate_limit to: AgentApi.config.rate_limit[:to], within: AgentApi.config.rate_limit[:within],
                 by: -> { current_credential.key_id }, store: AgentApi.rate_limit_store, name: "agent", scope: "agent_api",
                 with: -> { rate_limited!(AgentApi.config.rate_limit[:within]) }

      private

      attr_reader :current_credential

      def current_host = current_credential.host

      def authenticate_agent!
        @current_credential = AgentCredential.authenticate(request.authorization) or raise AgentApi::Unauthorized
        current_credential.record_use!
      end

      # For endpoints only active hosts may call (for example heartbeats, P1-HEARTBEAT).
      def require_active_host!
        raise AgentApi::HostNotActive unless current_host.enrollment_state == "active"
      end
    end
  end
end
