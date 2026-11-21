# Refreshes an exploitation signal (VT-SIGNALS, ADR 0032 point 5) from its URL setting: KevRefreshJob (CISA KEV, every 6
# hours after the advisory refresh) and EpssRefreshJob (FIRST EPSS, daily at 14:30 UTC), on the schedule in
# config/recurring.yml, after the advisory feed's "Refresh now" (Advisories::ManualRefresh, VT-D03), or from
# bin/rails signals:kev_refresh and signals:epss_refresh. Does nothing when the URL is empty: the last data is kept.
#
# Each is its own job, apart from the advisory and tracker refreshes, so a failure here never delays or blocks them or
# matching, and a signal never changes a finding (the triage run reads TriageSignalChange, #259).
#
# The download goes through Advisories::Feed: HTTPS with the certificate verified, a size limit, 15 minutes for the whole
# exchange, and redirects only to the hosts the signal allows (none for KEV; FLEET_EPSS_REDIRECT_HOSTS for EPSS). It is
# conditional on the validators of the latest successful import when that came from this feed and source and read
# cleanly; "not modified" is then recorded as a successful refresh (it stores nothing, so it is not audited), rechecked
# under the import lock. A failure (unreachable, timing out, an HTTP error, a file that cannot be read) is retried with
# backoff; after the last attempt it is recorded as a failed import, audited, and raised again, so it shows as a failed
# job. A held-back import, or an EPSS file older than the stored scores, is not a fault: the job ends normally.
#
# operator_id: the operator whose "Refresh now" ran it after the advisory feed: the import and any failure are theirs.
class SignalRefreshJob < ApplicationJob
  queue_as :default

  retry_on StandardError, wait: :polynomially_longer, attempts: ATTEMPTS do |job, error|
    job.give_up(error)
    raise error
  end

  def perform(allowed_drops: nil, operator_id: nil)
    @operator = operator_id && Operator.find_by(id: operator_id)
    feed = Signals.feed_for(signal)
    if feed.url.nil?
      logger.info("[signals] no #{label} configured (#{setting}); refresh skipped")
      return nil
    end

    @source = feed.source
    last = conditional_base
    download = feed.fetch(etag: last&.etag, last_modified: last&.last_modified)
    import = not_modified(last) if download.not_modified?
    if import.nil?
      if download.not_modified? # another import stored data since the request was made: the file is needed
        download.close!
        download = feed.fetch
      end
      import = import(download, allowed_drops)
    end
    logger.info("[signals] #{label} refresh from #{@source} #{import.state}: #{import.counts.to_json}")
    import
  rescue Signals::EpssImport::Older => e
    logger.warn("[signals] #{label} refresh from #{@source} refused: #{e.message}")
    Signals.record_failure(signal, reason: e.message, origin: "feed", source: @source, operator: @operator)
  rescue Advisories::Feed::Unavailable, Advisories::Unreadable => e
    logger.warn("[signals] #{label} refresh failed (attempt #{executions} of #{ATTEMPTS}): #{e.message}")
    raise
  ensure
    download&.close!
  end

  # Called by retry_on once the retries are used up, and by the rake tasks on their one attempt. Returns the failed
  # SignalImport.
  def give_up(error)
    reason = case error
    when Advisories::Feed::Unavailable, Advisories::Unreadable then error.message
    when *Signals::CONNECTION_ERRORS
      Signals.reconnect!
      Signals::CONNECTION_LOST
    else "the refresh failed on the server (#{error.class.name}); see the server log"
    end
    logger.error("[signals] #{label} refresh failed after #{[ executions, 1 ].max} attempts: #{reason}")
    @operator ||= (id = arguments.first.to_h.symbolize_keys[:operator_id]) && Operator.find_by(id:)
    Signals.record_failure(signal, reason:, origin: "feed", source: @source || Signals.feed_for(signal).source, operator: @operator)
  end

  private

  # The import whose validators may be sent, or nil: the latest import that stored or checked data, if it is a clean
  # success from this feed and source with nothing cleared since. After a file import, another URL, a held-back import,
  # malformed rows, or a clear (kev_clear, epss_reset), the whole file is needed again.
  def conditional_base
    latest = SignalImport.where(signal:, state: %w[succeeded held_back cleared]).order(finished_at: :desc, id: :desc).first
    return nil unless latest&.state == "succeeded" && latest.origin == "feed" && latest.source == @source
    return nil unless latest.counts["malformed"].to_i.zero?

    latest
  end

  # Records "not modified" as a refresh, under the import lock, if last is still the latest stored import; nil if
  # another import stored data meanwhile.
  def not_modified(last)
    SignalImport.transaction do
      Signals.lock!(signal)
      next nil unless conditional_base&.id == last.id

      now = Time.current
      SignalImport.create!(signal:, origin: "feed", source: @source, operator: @operator, state: "succeeded", counts: { "not_modified" => true },
                           version: last.version, score_date: last.score_date, etag: last.etag, last_modified: last.last_modified, started_at: now, finished_at: now)
    end
  end
end
