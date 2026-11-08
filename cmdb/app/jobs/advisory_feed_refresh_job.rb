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
# dashboard's "Refresh now". A scheduled run records itself as "scheduled" once (not again on retries, which are
# the same refresh; if recording fails, a retry records it instead, review of #125) and the rake task as "task";
# neither is ever refused. A manual refresh
# was recorded when the operator asked, and passes that attempt's id: its import and any failure are then
# attributed to that operator.
#
# A refresh that would withdraw too many advisories (Advisories::Import's guard, review of #129) is not a fault:
# nothing is written, the data stays as it was, and the refusal is recorded as a failed import with the counts
# per ecosystem and audited, but the job ends normally, so it is not retried and does not show as a failed job.
# The Data sources page and the freshness notice warn about it, and an operator can confirm the counts
# (Advisories::ManualRefresh.confirm_withdrawals!), which downloads the feed again with withdrawals allowed up to
# them (allowed_withdrawals).
#
# A manual refresh with triage: true (Advisories::ManualRefresh, P2-D08, owner decision T2 on #134) then refreshes
# Debian's triage: once this refresh is done, whatever its outcome (imported, not modified, held back, or failed
# after its last attempt), it enqueues DebianTriageRefreshJob once, attributed to the same operator. That job's
# failures are its own: they never change this refresh's outcome, and enqueueing it never fails this job.
class AdvisoryFeedRefreshJob < ApplicationJob
  queue_as :default

  retry_on StandardError, wait: :polynomially_longer, attempts: ATTEMPTS do |job, error|
    job.give_up(error)
    raise error
  end

  # attempt_id: the manual attempt Advisories::ManualRefresh.request! recorded. kind: what to record a run
  # without one as ("scheduled", or "task" from bin/rails advisories:refresh). allowed_withdrawals: per
  # ecosystem, how many advisories an operator confirmed this refresh may withdraw ({ "Debian:13" => 41 }).
  def perform(attempt_id: nil, kind: "scheduled", allowed_withdrawals: {}, triage: false)
    @triage = triage == true
    @allowed_withdrawals = allowed_withdrawals.to_h.transform_keys(&:to_s)
    feed = Advisories::Feed.new
    if feed.url.nil?
      logger.info("[advisories] no feed configured (FLEET_ADVISORY_FEED_URL); refresh skipped")
      return nil
    end

    if attempt_id
      @operator = AdvisoryRefreshAttempt.find_by(id: attempt_id)&.operator
    elsif !@start_recorded
      Advisories::ManualRefresh.record_start!(kind:)
      @start_recorded = true
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
    refresh_triage
    result
  rescue Advisories::Import::WithdrawalsRefused => e
    logger.warn("[advisories] feed refresh from #{@source} refused, nothing imported: #{e.message}")
    import = Advisories::Import.record_held_back(e, origin: "feed", source: @source, full: true, operator: @operator)
    refresh_triage
    Advisories::Import::Result.new(import:, changed_packages: {})
  rescue Advisories::Feed::Unavailable, Advisories::Unreadable => e
    logger.warn("[advisories] feed refresh failed (attempt #{executions} of #{ATTEMPTS}): #{e.message}")
    raise
  ensure
    download&.close!
  end

  # Whether this refresh's start is recorded travels with the job through its retries, as executions does.
  def serialize = super.merge("start_recorded" => @start_recorded == true)

  def deserialize(job_data)
    super
    @start_recorded = job_data["start_recorded"] == true
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
  ensure
    refresh_triage
  end

  private

  # The tracker refresh after a manual refresh that asked for it, once. Never raises: the OSV refresh's outcome
  # stands whatever happens here.
  def refresh_triage
    return unless @triage && !@triage_enqueued

    @triage_enqueued = true
    DebianTriageRefreshJob.perform_later(operator_id: @operator&.id)
  rescue StandardError => e
    logger.error("[advisories] could not start the Debian triage refresh after the feed refresh: #{e.class.name}: #{e.message}")
  end

  def import(download)
    Advisories::Import.new(origin: "feed", source: @source, full: true, operator: @operator, etag: download.etag, last_modified: download.last_modified,
                           allowed_withdrawals: @allowed_withdrawals)
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
