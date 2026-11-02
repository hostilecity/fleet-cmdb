# Shared pieces of the agent API (/api/v1): configuration, schemas, errors, and secret digests.
module AgentApi
  module_function

  def config = Rails.configuration.x.agent_api

  # The rate-limit counters. Tests use their own memory store because the test cache is a null store.
  def rate_limit_store
    @rate_limit_store ||= Rails.env.test? ? ActiveSupport::Cache::MemoryStore.new : Rails.cache
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
