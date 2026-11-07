# Refreshes advisory data from the configured feed (P2-S13, DEC-11), on the schedule in config/recurring.yml
# or from bin/rails advisories:refresh. Does nothing when no feed is configured.
#
# The download is conditional on the last successful one's validators: a "not modified" answer is recorded as
# a successful refresh of the same ecosystems, so freshness reflects that the data was checked (it imports
# nothing, so it is not audited). A download that had malformed records is not asked about conditionally. Imports are serialised by Advisories::Import's lock. A failure of
# any kind (the feed unreachable or timing out, an HTTP error, an archive that cannot be read) is retried with
# backoff; after the last attempt it is recorded as a failed import, audited, and raised again, so Solid Queue
# keeps it as a failed job and it shows on the dashboard banner and in /health (NFR-2, P1-O02).
#
# Each refresh records when it started (Advisories::ManualRefresh, P2-S15), which starts the cool-down on the
# dashboard's "Refresh now". A scheduled run records itself as "scheduled" on its first execution (not on
# retries, which are the same refresh) and the rake task as "task"; neither is ever refused. A manual refresh
# was recorded when the operator asked, and passes that attempt's id: its import and any failure are then
# attributed to that operator.
class AdvisoryFeedRefreshJob < ApplicationJob
  queue_as :default

  retry_on StandardError, wait: :polynomially_longer, attempts: ATTEMPTS do |job, error|
    job.give_up(error)
    raise error
  end

  # attempt_id: the manual attempt Advisories::ManualRefresh.request! recorded. kind: what to record a run
  # without one as ("scheduled", or "task" from bin/rails advisories:refresh).
  def perform(attempt_id: nil, kind: "scheduled")
    feed = Advisories::Feed.new
    if feed.url.nil?
      logger.info("[advisories] no feed configured (FLEET_ADVISORY_FEED_URL); refresh skipped")
      return nil
    end

    if attempt_id
      @operator = AdvisoryRefreshAttempt.find_by(id: attempt_id)&.operator
    elsif executions <= 1
      Advisories::ManualRefresh.record_start!(kind:)
    end
    @source = feed.source
    last = AdvisoryImport.succeeded.where(origin: "feed", source: @source).order(finished_at: :desc, id: :desc).first
    # Ask conditionally only when the last download imported cleanly: after malformed records, the same archive
    # is fetched again, so a fixed importer or a raised limit gets another chance at them and at the absence
    # sweep they blocked (review of #103).
    last = nil if last && last.counts["malformed"].to_i.positive?
    download = feed.fetch(etag: last&.etag, last_modified: last&.last_modified)
    result = download.not_modified? ? not_modified(last) : import(download)
    logger.info("[advisories] feed refresh from #{@source} succeeded: #{result.import.counts.to_json}")
    result
  rescue Advisories::Feed::Unavailable, Advisories::Unreadable => e
    logger.warn("[advisories] feed refresh failed (attempt #{executions} of #{ATTEMPTS}): #{e.message}")
    raise
  ensure
    download&.close!
  end

  # Called by retry_on once the retries are used up, and by bin/rails advisories:refresh on its one attempt.
  # Returns the failed AdvisoryImport.
  def give_up(error)
    reason = case error
    when Advisories::Feed::Unavailable, Advisories::Unreadable then error.message
    else "the refresh failed on the server (#{error.class.name}); see the server log"
    end
    attempts = [ executions, 1 ].max
    logger.error("[advisories] feed refresh failed after #{attempts} #{'attempt'.pluralize(attempts)}: #{reason}")
    Advisories::Import.record_failure(origin: "feed", source: @source || Advisories::Feed.new.source, reason:, full: true, operator: @operator)
  end

  private

  def import(download)
    Advisories::Import.new(origin: "feed", source: @source, full: true, operator: @operator, etag: download.etag, last_modified: download.last_modified)
                      .call(Advisories::Reader.new(download.file.path, name: File.basename(@source)))
  end

  # The archive has not changed since the last successful download: the data stays current.
  def not_modified(last)
    now = Time.current
    import = AdvisoryImport.create!(origin: "feed", source: @source, full: true, operator: @operator, state: "succeeded", ecosystems: last.ecosystems,
                                    counts: { "not_modified" => true }, etag: last.etag, last_modified: last.last_modified,
                                    started_at: now, finished_at: now)
    Advisories::Import::Result.new(import:, changed_packages: {})
  end
end
