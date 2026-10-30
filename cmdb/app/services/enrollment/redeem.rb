module Enrollment
  # Redeems an enrollment token for the host's permanent credential (POST /api/v1/enroll, DEC-04, P1-S05).
  #
  # In one transaction: the host and then the token are locked (the same order as everywhere else), the
  # token is marked used, any active credential is revoked (re-enrollment rotates the credential), a new
  # credential is created, and the host moves pending -> active with an audit entry. Unknown, expired, used, and retired-host tokens all raise the same error. Returns the credential
  # plaintext, which the caller returns to the agent once. After #call, #host is the host it was redeemed
  # for, so the caller never has to look it up again from the plaintext (review of #67).
  class Redeem
    def self.call(...) = new(...).call

    attr_reader :host

    def initialize(token:, machine_id:, agent_version:, schema_version:)
      @token = token
      @machine_id = machine_id
      @agent_version = agent_version
      @schema_version = schema_version
    end

    def call
      Host.transaction(requires_new: true) do
        # Lock order is host, then token, the same as Enrollment::IssueToken, so a token issued while
        # another is being redeemed cannot deadlock. The token is re-read under both locks.
        host_id = EnrollmentToken.host_id_for(@token) or raise AgentApi::EnrollmentTokenInvalid
        host = @host = Host.lock.find(host_id)
        record = EnrollmentToken.lock_for_redemption(@token)
        raise AgentApi::EnrollmentTokenInvalid unless record&.redeemable? && record.host_id == host.id
        raise AgentApi::EnrollmentTokenInvalid unless host.enrollment_state == "pending"

        record.update!(redeemed_at: Time.current)
        previous = host.agent_credentials.active.lock.to_a.each(&:revoke!)
        issued = AgentCredential.issue!(host:, machine_id: @machine_id)
        # A new credential starts a new machine identity, so any clone warning from the old one is cleared.
        host.update!(agent_version: @agent_version, agent_schema_version: @schema_version, machine_id_mismatch_at: nil, reported_machine_id: nil)
        host.activate!(actor: host, details: { "key_id" => [ previous.map(&:key_id).join(",").presence, issued.record.key_id ] })
        issued.plaintext
      end
    end
  end
end
