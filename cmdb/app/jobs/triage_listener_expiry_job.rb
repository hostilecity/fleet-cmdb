# Re-triages the hosts whose listener evidence (VT-APPLICABILITY, rule N5; owner decision 2026-11-21) turned 24 hours
# old (VulnerabilityTriage::LISTENER_FRESH), so a finding escalated by a scan that has not been repeated falls back to
# the rules without it. Hourly (config/recurring.yml). Each run covers the window (from, to]: from where the last run
# stopped (a row in triage_checkpoints; an hour back without one) to now - 24 hours, so a late or skipped run leaves no
# gap and evidence escalates for 24 hours to about 25. A clock that went back (to not after from) does nothing and
# keeps the checkpoint; a clock that jumped forward uses its window early: while it is ahead every match reads that
# evidence as expired anyway, and once it is back those hosts are not re-triaged at their real expiry, so their
# findings stay N5 until their next report (cautious). The hosts are queued in jobs of BATCH, so a mass expiry after an outage is many short jobs,
# each retried alone. Does nothing until #258 sets VulnerabilityTriage::HostFacts.listener_source.
class TriageListenerExpiryJob < ApplicationJob
  queue_as :default

  CHECKPOINT = "listener_expiry".freeze
  BATCH = 1_000

  def perform(now: Time.current)
    to = now - VulnerabilityTriage::LISTENER_FRESH
    from = TriageCheckpoint.at(CHECKPOINT) || to - 1.hour
    return [] unless to > from

    ids = VulnerabilityTriage::HostFacts.listener_hosts_expiring(from:, to:).uniq.sort
    ids.each_slice(BATCH) { |slice| VulnerabilityMatchJob.perform_later(host_ids: slice) }
    TriageCheckpoint.move!(CHECKPOINT, to)
    ids
  end
end
