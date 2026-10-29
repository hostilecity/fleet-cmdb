module Onboarding
  # The installer polls with its device code (POST /api/v1/onboarding/token, DEC-17). Returns a Result:
  #
  # - pending: still waiting for an operator. Polls faster than the interval raise RateLimited.
  # - approved: the credential, issued exactly once. In the same transaction a new host is created (pending,
  #   then active) with the operator's fields, or the re-enrolled host's credential is replaced (FR-1.1).
  #
  # Rejected requests raise OnboardingRejected. Unknown, expired, and already-collected device codes all raise
  # OnboardingExpired, so a response never reveals which.
  #
  # Lock order is the host (when the request names one), then the request, as in Approve. The host id is
  # read before locking; if an approval changes it in between, the attempt starts again.
  class Collect
    Result = Data.define(:status, :credential, :host) do
      def inspect = "#<Onboarding::Collect::Result status=#{status} [FILTERED]>"
      alias_method :to_s, :inspect
    end

    class HostChanged < StandardError; end

    ATTEMPTS = 3

    def self.call(...) = new(...).call

    def initialize(device_code:, agent_version:, schema_version:)
      @device_code = device_code
      @agent_version = agent_version
      @schema_version = schema_version
    end

    def call
      attempts = 0
      begin
        attempts += 1
        attempt
      rescue HostChanged
        retry if attempts < ATTEMPTS
        raise AgentApi::InternalError
      end
    end

    private

    def attempt
      found = OnboardingRequest.find_by_device_code(@device_code) or raise AgentApi::OnboardingExpired
      host_id = found.host_id
      OnboardingRequest.transaction(requires_new: true) do
        host = host_id && Host.lock.find(host_id)
        request = OnboardingRequest.lock.find(found.id)
        raise HostChanged if request.host_id != host_id

        now = Time.current
        case request.state
        when "rejected" then raise AgentApi::OnboardingRejected
        when "collected" then raise AgentApi::OnboardingExpired
        end
        raise AgentApi::OnboardingExpired if request.expired?(now)

        request.state == "open" ? pending(request, now) : issue(request, host, now)
      end
    end

    def pending(request, now)
      interval = OnboardingRequest.config.poll_interval
      raise AgentApi::RateLimited if request.last_polled_at && request.last_polled_at > now - interval

      request.update_column(:last_polled_at, now)
      Result.new(status: :pending, credential: nil, host: nil)
    end

    def issue(request, host, now)
      if request.reenroll
        # The operator retired or otherwise moved the host after approving: nothing to enroll any more.
        raise AgentApi::OnboardingExpired unless host.enrollment_state == "pending"
      else
        host = Host.register!(request.host_attributes, actor: request.decided_by || Audit::SYSTEM)
      end

      previous = host.agent_credentials.active.lock.to_a.each(&:revoke!)
      issued = AgentCredential.issue!(host:, machine_id: request.machine_id)
      # A new credential starts a new machine identity, so any clone warning from the old one is cleared.
      host.update!(agent_version: @agent_version, agent_schema_version: @schema_version, machine_id_mismatch_at: nil, reported_machine_id: nil)
      host.activate!(actor: host, details: { "key_id" => [ previous.map(&:key_id).join(",").presence, issued.record.key_id ],
                                             "onboarding_request_id" => [ nil, request.id ] })
      request.update!(state: "collected", collected_at: now, host:)
      Result.new(status: :approved, credential: issued.plaintext, host:)
    end
  end
end
