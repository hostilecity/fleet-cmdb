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

  class ValidationFailed < Error
    self.status = :bad_request
    self.code = "validation_failed"
    self.default_message = "The request body is invalid."
  end

  class Unauthorized < Error
    self.status = :unauthorized
    self.code = "unauthorized"
    self.default_message = "Missing or invalid credential."
  end

  class HostNotActive < Error
    self.status = :forbidden
    self.code = "host_not_active"
    self.default_message = "This host is not active."
  end

  # A pending host whose old credential still works (re-enrollment, FR-1.1). The agent must redeem the new
  # enrollment token; the response also carries Fleet-Enrollment-State: pending.
  class ReenrollmentRequired < Error
    self.status = :forbidden
    self.code = "reenrollment_required"
    self.default_message = "This host is being re-enrolled. Redeem the new enrollment token (fleet-agent enroll --force)."
  end

  class NotFound < Error
    self.status = :not_found
    self.code = "not_found"
    self.default_message = "No such endpoint."
  end

  class EnrollmentTokenInvalid < Error
    self.status = :gone
    self.code = "enrollment_token_invalid"
    self.default_message = "The enrollment token is invalid, expired, or already used."
  end

  class PayloadTooLarge < Error
    self.status = :payload_too_large
    self.code = "payload_too_large"
    self.default_message = "The request body is too large."
  end

  class AgentVersionUnsupported < Error
    self.status = :upgrade_required
    self.code = "agent_version_unsupported"
    self.default_message = "This agent version is no longer supported. Upgrade the agent."
  end

  class RateLimited < Error
    self.status = :too_many_requests
    self.code = "rate_limited"
    self.default_message = "Too many requests. Retry later."
  end

  class InternalError < Error
    self.status = :internal_server_error
    self.code = "internal_error"
    self.default_message = "Something went wrong on the server."
  end
end
