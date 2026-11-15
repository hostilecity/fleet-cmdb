# Shared pieces of the agent API (/api/v1): configuration, schemas, errors, and secret digests.
module AgentApi
  module_function

  def config = Rails.configuration.x.agent_api

  # The rate-limit counters for enrollment, onboarding, and release downloads: Rails.cache, so shared by every server
  # process. Tests use their own memory store because the test cache is a null store.
  def rate_limit_store
    @rate_limit_store ||= Rails.env.test? ? ActiveSupport::Cache::MemoryStore.new : Rails.cache
  end

  LIMITERS = Mutex.new
  # Failed authentications are counted for at most this many client addresses per process (#191).
  FAILED_AUTH_MAX_ADDRESSES = 10_000

  # The per-credential limit on authenticated endpoints, in this process's memory (RateLimiter, #191).
  def credential_rate_limiter
    @credential_rate_limiter || LIMITERS.synchronize { @credential_rate_limiter ||= RateLimiter.new(max_keys: config.rate_limit_max_keys) }
  end

  # The per-address limit on failed authentication (server finding S-5), in this process's memory (#191).
  def failed_auth_rate_limiter
    @failed_auth_rate_limiter || LIMITERS.synchronize { @failed_auth_rate_limiter ||= RateLimiter.new(max_keys: FAILED_AUTH_MAX_ADDRESSES) }
  end

  # How long a key id counts as recently authenticated (review of #211): longer than an agent's default gap between
  # requests (a heartbeat a minute, a task poll every 5 minutes), so a working agent is never forgotten between two.
  RECENT_CREDENTIAL_TTL = 15.minutes

  # The key ids that authenticated in this process within RECENT_CREDENTIAL_TTL. A request whose key id is here
  # passes an address's failed-authentication block, so a hostile client sharing the agents' address cannot lock
  # them out. Only key ids that authenticated are added, so hostile input cannot grow it.
  def recent_credentials
    @recent_credentials || LIMITERS.synchronize { @recent_credentials ||= RateLimiter.new(max_keys: config.rate_limit_max_keys) }
  end

  # Credentials and tokens are long random values, so a plain SHA-256 digest is appropriate (FR-S.1).
  def digest(secret) = OpenSSL::Digest::SHA256.hexdigest(secret)

  # Errors rendered as the documented envelope (docs/api/README.md, "Errors"). Messages are fixed strings and
  # never contain request values or internals.
  class Error < StandardError
    class_attribute :status, :code, :default_message

    attr_reader :details

    def initialize(message = nil, details: nil)
      super(message || default_message)
      @details = details
    end
  end

  # One error class per documented code: AgentApi::Unauthorized and so on, rescued and rendered by status and code.
  def self.error(status, code, default_message) = Class.new(Error) { self.status, self.code, self.default_message = status, code, default_message }

  ValidationFailed = error(:bad_request, "validation_failed", "The request body is invalid.")
  Unauthorized = error(:unauthorized, "unauthorized", "Missing or invalid credential.")
  HostNotActive = error(:forbidden, "host_not_active", "This host is not active.")
  # A pending host whose old credential still works (re-enrollment, FR-1.1). The agent must be re-enrolled,
  # by onboarding or with the new enrollment token; the response also carries Fleet-Enrollment-State: pending.
  ReenrollmentRequired = error(:forbidden, "reenrollment_required",
                               "This host is being re-enrolled. On the VM, run `fleet-agent install --reenroll`, or `fleet-agent install --token` with the new token.")
  NotFound = error(:not_found, "not_found", "No such endpoint.")
  # A task id that does not exist or belongs to another host: one response for both (FR-S.2, P3-S03).
  TaskNotFound = error(:not_found, "not_found", "No such task.")
  # A task result that differs from the one already recorded, or that the task's state cannot take (P3-S04).
  TaskConflict = error(:conflict, "task_conflict", "This task cannot take that result.")
  EnrollmentTokenInvalid = error(:gone, "enrollment_token_invalid", "The enrollment token is invalid, expired, or already used.")
  # Onboarding (DEC-17, P1-ONBOARD): an operator rejected the request.
  OnboardingRejected = error(:forbidden, "onboarding_rejected", "An operator rejected this onboarding request.")
  # Unknown, expired, and already-collected device codes all get this one response.
  OnboardingExpired = error(:gone, "onboarding_expired", "This onboarding request has expired or was already used. Run the installer again.")
  PayloadTooLarge = error(:content_too_large, "payload_too_large", "The request body is too large.")
  AgentVersionUnsupported = error(:upgrade_required, "agent_version_unsupported", "This agent version is no longer supported. Upgrade the agent.")
  RateLimited = error(:too_many_requests, "rate_limited", "Too many requests. Retry later.")
  InternalError = error(:internal_server_error, "internal_error", "Something went wrong on the server.")
end
