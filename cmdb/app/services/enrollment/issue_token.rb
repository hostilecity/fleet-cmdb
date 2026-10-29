module Enrollment
  # Issues an enrollment token for a host and returns the plaintext once (DEC-04, P1-S05).
  #
  # For an active or revoked host this starts re-enrollment (FR-1.1: -> pending). An active host's credential
  # keeps working until the new token is redeemed. Any earlier unredeemed token for the host, and any approved
  # but uncollected onboarding re-enrollment of it, is expired, so only the newest path works.
  class IssueToken
    class HostRetired < StandardError; end

    def self.call(...) = new(...).call

    def initialize(host:, actor:, ttl: Rails.configuration.x.enrollment.token_ttl)
      @host = host
      @actor = actor
      @ttl = ttl
    end

    def call
      Host.transaction(requires_new: true) do
        @host.lock!
        raise HostRetired, "retired hosts cannot be enrolled" if @host.retired?

        transitioning = @host.can_transition?(:begin_reenrollment)
        @host.begin_reenrollment!(actor: @actor) if transitioning
        @host.enrollment_tokens.redeemable.update_all(expires_at: Time.current, updated_at: Time.current)
        # An approved onboarding re-enrollment of this host is superseded too (DEC-17, review of #61).
        OnboardingRequest.supersede_reenrollments!(@host)
        issued = EnrollmentToken.issue!(host: @host, ttl: @ttl)
        Audit.record(actor: @actor, action: Audit::Actions::HOST_ENROLLMENT_TOKEN_ISSUED, target: @host,
                     changes: { "expires_at" => [ nil, issued.record.expires_at ] })
        # A new or pending host changes no state here, but open dashboards show its row, counts, and token
        # expiry, so they refresh too (review of #63). A transition above has already asked for that.
        FleetBroadcast.hosts_changed([ @host.id ]) unless transitioning
        issued.plaintext
      end
    end
  end
end
