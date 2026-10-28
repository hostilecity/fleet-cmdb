# Removes onboarding requests a day after they expired, whatever their state (DEC-17, P1-ONBOARD). The day
# lets a late poll still get its documented answer; after that an unknown device code gets the same 410.
# Decisions stay in the audit log.
class OnboardingPruneJob < ApplicationJob
  queue_as :default

  KEEP_AFTER_EXPIRY = 1.day

  def perform(now: Time.current)
    deleted = OnboardingRequest.where(expires_at: ...(now - KEEP_AFTER_EXPIRY)).delete_all
    logger.info("[onboarding] pruned #{deleted} expired requests") if deleted.positive?
    deleted
  end
end
