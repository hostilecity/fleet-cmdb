# Re-triages the hosts whose listener evidence (VT-APPLICABILITY, rule N5; owner decision 2026-11-21) turned 24 hours
# old (VulnerabilityTriage::LISTENER_FRESH), so a finding escalated by a scan that has not been repeated falls back to
# the rules without it. Hourly (config/recurring.yml). Each run covers the window (from, to]: from where the last run
# stopped (a row in triage_checkpoints, moved forward only; an hour back without one) to now - 24 hours, so a late or
# skipped run leaves no gap and evidence escalates for 24 hours to about 25.
#
# Clock jumps (fifth review of #277): a checkpoint ahead of to (the clock went back, or a jump forward was corrected
# after a run had moved the checkpoint) is logged and reset to to, and the run covers the hour before it. Without that,
# the durable checkpoint would stop this job expiring any host's evidence for as long as the jump lasted. A forward
# jump still uses its window early: while the clock is ahead every match reads that evidence as expired anyway, and
# the hosts whose window was used then are not re-triaged at their real expiry, so their findings stay N5 until their
# evidence or package set next changes (record_in_use! signals a change of evidence, not a newer scan time alone).
# The hosts are queued in jobs of BATCH, so a mass expiry after an outage is many short jobs, each retried alone. Does
# nothing until #258 sets VulnerabilityTriage::HostFacts.listener_source.
class TriageListenerExpiryJob < ApplicationJob
  queue_as :default

  CHECKPOINT = "listener_expiry".freeze
  BATCH = 1_000

  def perform(now: Time.current)
    to = now - VulnerabilityTriage::LISTENER_FRESH
    from = TriageCheckpoint.at(CHECKPOINT)
    if from && from > to
      Rails.logger.warn("[triage] listener expiry checkpoint #{from.iso8601} is ahead of the clock (#{to.iso8601}): reset")
      TriageCheckpoint.reset!(CHECKPOINT, to)
      from = nil
    end
    from ||= to - 1.hour
    return [] unless to > from

    ids = VulnerabilityTriage::HostFacts.listener_hosts_expiring(from:, to:).uniq.sort
    ids.each_slice(BATCH) { |slice| VulnerabilityMatchJob.perform_later(host_ids: slice) }
    TriageCheckpoint.move!(CHECKPOINT, to)
    ids
  end
end
