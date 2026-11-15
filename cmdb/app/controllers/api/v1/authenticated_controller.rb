module Api
  module V1
    # Base for every endpoint an agent calls with its credential (FR-S.1, FR-S.2, P1-S04).
    #
    # The host is always the one the credential belongs to (#current_host). Never look a host up from the
    # request: no endpoint takes a host identifier, so one host cannot read or write another's data (AC-1.6).
    # Missing, malformed, unknown, revoked, and retired-host credentials all get the same 401, and there is
    # no authentication cache, so revocation takes effect on the next request (AC-1.5).
    #
    # One transaction per request (#189). For the actions a controller declares `atomic`, the transaction opens
    # before authentication and closes after the action, so authentication, the host lock (AgentHostLock), the
    # writes, and the credential's last use commit once. Authentication still comes first, before the body is
    # read, and takes no lock; the action locks the host and re-checks the credential under that lock.
    class AuthenticatedController < BaseController
      # Whether a request updates the credential's last_used_at. Heartbeats opt out: they record
      # hosts.last_seen_at instead and must stay a single write (P1-S07, review of #50).
      class_attribute :records_credential_use, default: true
      # The actions that run in one transaction, authentication included (see .atomic).
      class_attribute :atomic_actions, default: [].freeze

      # Refusals found under the host row lock (AgentHostLock), mapped to the documented errors.
      REFUSALS = {
        unauthorized: AgentApi::Unauthorized,
        reenrollment_required: AgentApi::ReenrollmentRequired,
        host_not_active: AgentApi::HostNotActive
      }.freeze

      # The failed-authentication counter's key, per client address (S-5).
      FAILED_AUTH_KEY = "failed-auth:%s".freeze

      rescue_from(AgentHostLock::Refused) { |refusal| render_api_error(REFUSALS.fetch(refusal.reason).new) }

      # S-5 (#191): an address that failed authentication too often in the window is refused before anything else,
      # with no database work, until the window ends. Only failures are counted, but once an address is over the
      # limit its requests with a valid credential are refused too.
      before_action :refuse_after_failed_authentications
      # Declared before authentication, so it wraps authentication and every later callback as well as the action.
      around_action :in_request_transaction
      before_action :authenticate_agent!
      # Per credential, in this process's memory (AgentApi::RateLimiter, #191): no database write per request.
      limits_rate "agent", AgentApi.config.rate_limit, by: -> { current_credential.key_id }, store: AgentApi.credential_rate_limiter

      # Unlike BaseController.atomic, which wraps only the action, the transaction here starts before authentication.
      def self.atomic(*actions)
        self.atomic_actions = (atomic_actions + actions.map(&:to_s)).freeze
      end

      private

      attr_reader :current_credential

      def current_host = current_credential.host

      def authenticate_agent!
        @current_credential = AgentCredential.authenticate(request.authorization) or failed_authentication!
        Current.host_id = current_credential.host_id
      end

      def refuse_after_failed_authentications
        limit = AgentApi.config.failed_auth_rate_limit
        rate_limited!(limit[:within]) if AgentApi.failed_auth_rate_limiter.count(format(FAILED_AUTH_KEY, request.remote_ip)) >= limit[:to]
      end

      def failed_authentication!
        AgentApi.failed_auth_rate_limiter.increment(format(FAILED_AUTH_KEY, request.remote_ip), 1, expires_in: AgentApi.config.failed_auth_rate_limit[:within])
        raise AgentApi::Unauthorized
      end

      # The credential's last use is written after the action, in its transaction: every atomic action has locked
      # the host by then, so the credential row is taken after the host row, as revocation takes them.
      def in_request_transaction(&)
        return run_and_record_use(&) unless atomic_actions.include?(action_name)

        ApplicationRecord.transaction { run_and_record_use(&) }
      end

      def run_and_record_use
        yield
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
