module Enrollment
  # Redeems an enrollment token for the host's permanent credential (POST /api/v1/enroll, DEC-04, P1-S05).
  #
  # In one transaction: the token is locked and marked used, any active credential is revoked (re-enrollment
  # rotates the credential), a new credential is created, and the host moves pending -> active with an audit
  # entry. Unknown, expired, used, and retired-host tokens all raise the same error. Returns the credential
  # plaintext, which the caller returns to the agent once.
  class Redeem
    def self.call(...) = new(...).call

    def initialize(token:, machine_id:, agent_version:, schema_version:)
      @token = token
      @machine_id = machine_id
      @agent_version = agent_version
      @schema_version = schema_version
    end

    def call
      Host.transaction(requires_new: true) do
        record = EnrollmentToken.lock_for_redemption(@token)
        raise AgentApi::EnrollmentTokenInvalid unless record&.redeemable?

        host = record.host.lock!
        raise AgentApi::EnrollmentTokenInvalid unless host.enrollment_state == "pending"

        record.update!(redeemed_at: Time.current)
        previous = host.agent_credentials.active.lock.to_a.each(&:revoke!)
        issued = AgentCredential.issue!(host:, machine_id: @machine_id)
        host.update!(agent_version: @agent_version, agent_schema_version: @schema_version)
        host.activate!(actor: host, details: { "key_id" => [ previous.map(&:key_id).join(",").presence, issued.record.key_id ] })
        issued.plaintext
      end
    end
  end
end
