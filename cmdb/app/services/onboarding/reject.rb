module Onboarding
  # An operator rejects an onboarding request (DEC-17). The installer's next poll gets 403
  # onboarding_rejected. Nothing else changes.
  class Reject
    include Decide

    def self.call(...) = new(...).call

    def initialize(request:, operator:)
      @request = request
      @operator = operator
    end

    def call
      with_request_locked(@request) do
        @request.update!(state: "rejected", decided_by: @operator, decided_at: Time.current)
        Audit.record(actor: @operator, action: Audit::Actions::ONBOARDING_REJECTED, target: @request, changes: { "state" => %w[open rejected] })
        FleetBroadcast.refresh
        @request
      end
    end
  end
end
