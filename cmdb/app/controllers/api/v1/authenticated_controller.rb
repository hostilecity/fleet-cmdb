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
      # host_liveness.last_seen_at instead (#192) and must stay a single write (P1-S07, review of #50).
      class_attribute :records_credential_use, default: true
      # The actions that run in one transaction, authentication included (see .atomic).
      class_attribute :atomic_actions, default: [].freeze
      # Report endpoints: shed when too many reports are in flight in this process (AgentApi::ReportShedding, #200).
      class_attribute :sheds_report_load, default: false

      # Refusals found under the host row lock (AgentHostLock), mapped to the documented errors.
      REFUSALS = {
        unauthorized: AgentApi::Unauthorized,
        reenrollment_required: AgentApi::ReenrollmentRequired,
        host_not_active: AgentApi::HostNotActive
      }.freeze

      # The failed-authentication counters' keys: per client address (an IPv6 address per /64, which one host can
      # hold whole), and per recently authenticated key id (S-5, review of #211).
      FAILED_AUTH_KEY = "failed-auth:%s".freeze
      FAILED_AUTH_KEY_ID = "failed-auth-key:%s".freeze

      rescue_from(AgentHostLock::Refused) { |refusal| render_api_error(REFUSALS.fetch(refusal.reason).new) }

      # S-5 (#191): an address that failed authentication too often in the window is refused before anything else,
      # with no database work, until the window ends. Only failures are counted. A request whose key id authenticated
      # in this process recently (AgentApi.recent_credentials) still goes on to authentication, so a client sharing
      # the agents' address (a NAT, a proxy) cannot lock them out; that key id's own failures are counted, and past
      # the limit it no longer passes (review of #211).
      before_action :refuse_after_failed_authentications
      # After the failed-authentication check, before authentication and the transaction (review of #208).
      around_action :shed_report_load, if: :sheds_report_load
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

      def shed_report_load(&)
        taken, wait = AgentApi::ReportShedding.within_limit(&)
        return if taken

        logger.warn("[agent_api] shed #{request.path}: #{AgentApi::ReportShedding::GAUGE.count} reports in flight; retry after #{wait}s")
        @retry_after = wait
        raise AgentApi::Overloaded
      end

      def authenticate_agent!
        @current_credential = AgentCredential.authenticate(request.authorization) or failed_authentication!
        AgentApi.recent_credentials.remember(current_credential.key_id, expires_in: AgentApi::RECENT_CREDENTIAL_TTL)
        Current.host_id = current_credential.host_id
      end

      # touch: a blocked address that keeps trying stays the most recently used key, so failures from other addresses
      # cannot push it out of the limiter and reset its block (review of #211).
      def refuse_after_failed_authentications
        limit = AgentApi.config.failed_auth_rate_limit
        return if AgentApi.failed_auth_rate_limiter.count(format(FAILED_AUTH_KEY, client_address), touch: true) < limit[:to]
        return if recent_key_id && AgentApi.failed_auth_rate_limiter.count(format(FAILED_AUTH_KEY_ID, recent_key_id)) < limit[:to]

        rate_limited!(limit[:within])
      end

      # Counted per address, and per key id when that key id authenticated recently (only those, so random key ids
      # cannot fill the limiter).
      def failed_authentication!
        within = AgentApi.config.failed_auth_rate_limit[:within]
        AgentApi.failed_auth_rate_limiter.increment(format(FAILED_AUTH_KEY, client_address), 1, expires_in: within)
        AgentApi.failed_auth_rate_limiter.increment(format(FAILED_AUTH_KEY_ID, recent_key_id), 1, expires_in: within) if recent_key_id
        raise AgentApi::Unauthorized
      end

      # The key id in the Authorization header, read without the database, if it authenticated in this process within
      # AgentApi::RECENT_CREDENTIAL_TTL; otherwise nil.
      def recent_key_id
        return @recent_key_id if defined?(@recent_key_id)

        key_id = AgentCredential::BEARER.match(request.authorization.to_s)&.captures&.first
        @recent_key_id = key_id if key_id && AgentApi.recent_credentials.live?(key_id)
      end

      # The address the failed-authentication limit counts: the client's IPv4 address, or its IPv6 /64.
      def client_address
        @client_address ||= begin
          ip = IPAddr.new(request.remote_ip)
          ip = ip.native if ip.ipv4_mapped?
          ip.ipv6? ? "#{ip.mask(64)}/64" : ip.to_s
        rescue IPAddr::Error
          request.remote_ip.to_s
        end
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
