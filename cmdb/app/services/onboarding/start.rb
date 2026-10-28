module Onboarding
  # Starts an onboarding request for an installer (POST /api/v1/onboarding, DEC-17). The endpoint is
  # unauthenticated, so this creates no host and is capped: at most max_open requests awaiting approval in
  # total and max_open_per_address from one client address. The caps are checked under a transaction-level
  # advisory lock, so concurrent starts cannot overshoot them. Returns OnboardingRequest::Started; the
  # device code in it is shown to the installer once and stored only as a digest.
  class Start
    LOCK_KEY = 0x6f6e6264 # "onbd"
    USER_CODE_ATTEMPTS = 5

    def self.call(...) = new(...).call

    def initialize(facts:, client_ip:, now: Time.current)
      @facts = facts
      @client_ip = client_ip.to_s
      @now = now
    end

    def call
      OnboardingRequest.transaction(requires_new: true) do
        OnboardingRequest.connection.execute("SELECT pg_advisory_xact_lock(#{LOCK_KEY})")
        enforce_caps!
        device_code = SecureRandom.urlsafe_base64(32)
        record = create_with_unique_user_code(device_code)
        OnboardingRequest::Started.new(record:, device_code:)
      end
    end

    private

    def config = OnboardingRequest.config

    def enforce_caps!
      awaiting = OnboardingRequest.awaiting(@now)
      return if awaiting.count < config.max_open && awaiting.where(client_ip: @client_ip).count < config.max_open_per_address

      raise AgentApi::RateLimited
    end

    # User codes are unique among open requests (a partial unique index); a collision is retried with a new
    # code inside a savepoint. With 20^8 codes and a small cap on open requests, a retry is very rare.
    def create_with_unique_user_code(device_code)
      attempts = 0
      begin
        attempts += 1
        OnboardingRequest.transaction(requires_new: true) { OnboardingRequest.create!(attributes(device_code)) }
      rescue ActiveRecord::RecordNotUnique
        retry if attempts < USER_CODE_ATTEMPTS
        raise
      end
    end

    def attributes(device_code)
      os = @facts["os"]
      {
        device_code_digest: AgentApi.digest(device_code),
        user_code: OnboardingRequest.generate_user_code,
        hostname: OnboardingRequest.clean(@facts["hostname"], 253),
        machine_id: @facts["machine_id"],
        os: os && %w[id version_id pretty_name].index_with { |k| OnboardingRequest.clean(os[k], k == "pretty_name" ? 256 : 64) },
        agent_version: @facts["agent_version"],
        client_ip: @client_ip.first(45),
        expires_at: @now + config.ttl
      }
    end
  end
end
