# Re-triages the hosts whose listener evidence (VT-APPLICABILITY, rule N5; owner decision 2026-11-21) turned 24 hours
# old (VulnerabilityTriage::LISTENER_FRESH), so a finding escalated by a scan that has not been repeated falls back to
# the rules without it. Hourly (config/recurring.yml). Each run covers from where the last one stopped (a checkpoint in
# the cache; an hour back without one) to now - 24 hours, so a late or skipped run leaves no gap: evidence escalates
# for 24 hours to about 25. The hosts are queued in jobs of BATCH, so a mass expiry after an outage is many short jobs,
# each retried alone. Does nothing until #258 sets VulnerabilityTriage::HostFacts.listener_source.
class TriageListenerExpiryJob < ApplicationJob
  queue_as :default

  CHECKPOINT = "triage/listener_expiry/to".freeze
  BATCH = 1_000

  def perform(now: Time.current)
    to = now - VulnerabilityTriage::LISTENER_FRESH
    from = Rails.cache.read(CHECKPOINT) || to - 1.hour
    ids = VulnerabilityTriage::HostFacts.listener_hosts_expiring(from:, to:).uniq.sort
    ids.each_slice(BATCH) { |slice| VulnerabilityMatchJob.perform_later(host_ids: slice) }
    Rails.cache.write(CHECKPOINT, to)
    ids
  end
end
