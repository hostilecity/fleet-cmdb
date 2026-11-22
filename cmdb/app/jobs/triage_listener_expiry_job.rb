# Re-triages the hosts whose listener evidence (VT-APPLICABILITY, rule N5; owner decision 2026-11-21) turned 24 hours
# old since the last run (VulnerabilityTriage::LISTENER_FRESH), so a finding escalated by a listener that has not been
# seen again falls back to the rules without it. Hourly (config/recurring.yml); each run covers the hour before it and
# overlaps the last by EXPIRY_OVERLAP, so a late run misses nothing (a host re-triaged twice changes nothing the second
# time). Does nothing until #258 sets VulnerabilityTriage::HostFacts.listener_source.
class TriageListenerExpiryJob < ApplicationJob
  queue_as :default

  EXPIRY_OVERLAP = 10.minutes

  def perform(now: Time.current)
    ids = VulnerabilityTriage::HostFacts.listener_hosts_expiring(from: now - VulnerabilityTriage::LISTENER_FRESH - 1.hour - EXPIRY_OVERLAP,
                                                                 to: now - VulnerabilityTriage::LISTENER_FRESH)
    VulnerabilityMatchJob.perform_later(host_ids: ids.uniq.sort) if ids.any?
    ids
  end
end
