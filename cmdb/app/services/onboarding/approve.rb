module Onboarding
  # An operator approves an onboarding request (DEC-17, P1-D07 calls this), either as a new host with the
  # fields entered on the approval page, or as the re-enrollment of an existing host the operator chose.
  # Matching an existing host by machine ID or hostname is only ever offered to the operator, never applied
  # here on its own.
  #
  # Nothing is created yet: the host appears, or the target host gets its new credential, when the installer
  # collects (Onboarding::Collect). For a re-enrollment the target moves to pending now, as when a new
  # enrollment token is issued (FR-1.1): its old credential keeps working until collection, and any unused
  # enrollment token for it, and any earlier approved re-enrollment of it, stops working, so only the newest
  # path can enroll it.
  class Approve
    include Decide

    class TargetRetired < StandardError; end

    def self.call(...) = new(...).call

    # attributes: name, hostname, tags, description, notes for a new host (hostname defaults to the reported
    # one). Ignored when re-enrolling target_host, which keeps its own fields.
    def initialize(request:, operator:, attributes: {}, target_host: nil)
      @request = request
      @operator = operator
      @attributes = attributes.to_h.stringify_keys.slice(*Host::EDITABLE_ATTRIBUTES)
      @target = target_host
    end

    def call
      with_request_locked(@request, host: @target) do
        @target ? prepare_reenrollment : validate_new_host!
        @request.update!(state: "approved", decided_by: @operator, decided_at: Time.current,
                         host_attributes: @target ? nil : @host_attributes, reenroll: @target.present?, host: @target)
        Audit.record(actor: @operator, action: Audit::Actions::ONBOARDING_APPROVED, target: @request,
                     changes: { "state" => %w[open approved], "host_id" => [ nil, @target&.id ], "reenroll" => [ nil, @target.present? ] })
        @request
      end
    end

    private

    def prepare_reenrollment
      raise TargetRetired, "retired hosts cannot be re-enrolled" if @target.retired?

      @target.begin_reenrollment!(actor: @operator) if @target.can_transition?(:begin_reenrollment)
      @target.enrollment_tokens.redeemable.update_all(expires_at: Time.current, updated_at: Time.current)
      OnboardingRequest.supersede_reenrollments!(@target)
    end

    # Validated now, so the operator sees errors on the approval page rather than the installer failing at
    # collection. The normalised values (squished name, cleaned tags) are what the host is created with.
    def validate_new_host!
      host = Host.new({ "hostname" => @request.hostname }.merge(@attributes.compact_blank))
      host.validate!
      @host_attributes = host.slice(*Host::EDITABLE_ATTRIBUTES)
    end
  end
end
