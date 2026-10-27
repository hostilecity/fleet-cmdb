module Api
  module V1
    # Base for every endpoint an agent calls with its credential (FR-S.1, FR-S.2, P1-S04).
    #
    # The host is always the one the credential belongs to (#current_host). Never look a host up from the
    # request: no endpoint takes a host identifier, so one host cannot read or write another's data (AC-1.6).
    # Missing, malformed, unknown, revoked, and retired-host credentials all get the same 401, and there is
    # no authentication cache, so revocation takes effect on the next request (AC-1.5).
    class AuthenticatedController < BaseController
      # Whether a request updates the credential's last_used_at. Heartbeats opt out: they record
      # hosts.last_seen_at instead and must stay a single write (P1-S07, review of #50).
      class_attribute :records_credential_use, default: true

      # Refusals found under the host row lock (AgentHostLock), mapped to the documented errors.
      REFUSALS = {
        unauthorized: AgentApi::Unauthorized,
        reenrollment_required: AgentApi::ReenrollmentRequired,
        host_not_active: AgentApi::HostNotActive
      }.freeze

      rescue_from(AgentHostLock::Refused) { |refusal| render_api_error(REFUSALS.fetch(refusal.reason).new) }

      before_action :authenticate_agent!
      rate_limit to: AgentApi.config.rate_limit[:to], within: AgentApi.config.rate_limit[:within],
                 by: -> { current_credential.key_id }, store: AgentApi.rate_limit_store, name: "agent", scope: "agent_api",
                 with: -> { rate_limited!(AgentApi.config.rate_limit[:within]) }

      private

      attr_reader :current_credential

      def current_host = current_credential.host

      def authenticate_agent!
        @current_credential = AgentCredential.authenticate(request.authorization) or raise AgentApi::Unauthorized
        current_credential.record_use! if records_credential_use
      end

      # For endpoints only active hosts may call (for example heartbeats, P1-HEARTBEAT). A pending host can
      # only get here mid re-enrollment (its old credential works until the new token is redeemed), so it is
      # told to redeem the new token rather than given a generic refusal.
      def require_active_host!
        case current_host.enrollment_state
        when "active" then nil
        when "pending" then raise AgentApi::ReenrollmentRequired
        else raise AgentApi::HostNotActive
        end
      end
    end
  end
end
