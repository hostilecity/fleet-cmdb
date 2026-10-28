module Onboarding
  # Raised by Approve and Reject when the request can no longer be decided: it expired, or was already
  # approved, rejected, or collected. The dashboard shows the request's current state instead (P1-D07).
  class NotDecidable < StandardError; end

  # Shared locking for operator decisions. Lock order is the host (when re-enrolling one), then the request,
  # the same order Onboarding::Collect uses, so decisions and collections cannot deadlock.
  module Decide
    private

    def with_request_locked(request, host: nil)
      OnboardingRequest.transaction(requires_new: true) do
        host&.lock!
        request.lock!
        raise NotDecidable, "this onboarding request can no longer be decided" unless request.awaiting?

        yield
      end
    end
  end
end
