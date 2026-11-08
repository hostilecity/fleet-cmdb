# Refreshes the Debian Security Tracker's triage (P2-S16, ADR 0022) from FLEET_DEBIAN_TRACKER_URL, on the schedule
# in config/recurring.yml (after the OSV refresh) or from bin/rails advisories:triage_refresh. Does nothing when
# no URL is configured.
#
# It is its own job, apart from AdvisoryFeedRefreshJob, so a failure here never delays or blocks an OSV refresh or
# matching, and triage never enqueues matching: it changes no finding.
#
# The download is one document, over HTTPS with the certificate verified, at most FLEET_DEBIAN_TRACKER_MAX_DOWNLOAD_MB,
# within Advisories::Feed's time limits, and conditional on the validators of the latest import that stored data,
# from any origin or source, only when that import came from this feed and was a clean success of the same
# releases: "not modified" is then recorded as a successful refresh of those releases, so freshness reflects that
# the data was checked (it stores nothing, so it is not audited). That is rechecked under the import lock before
# it is recorded; if another import stored data meanwhile, the document is downloaded again without validators
# (review of #135: otherwise a file import after a feed import could be renewed as fresh forever). A failure (the
# tracker unreachable or timing out, an HTTP error, a document that cannot be read) is retried with backoff; after
# the last attempt it is recorded as a failed import, audited, and raised again, so it shows as a failed job.
#
# A held-back import (the truncation guard in DebianTriage::Import) is not a fault: the job ends normally, so it
# is not retried and does not show as a failed job. allowed_drops is an operator's confirmation of the counts,
# from bin/rails advisories:triage_refresh ALLOW_DROPS=...
#
# operator_id: the operator whose "Refresh now" ran it right after the advisory feed (P2-D08, T2): the import and
# any failure are attributed to them.
class DebianTriageRefreshJob < ApplicationJob
  queue_as :default

  retry_on StandardError, wait: :polynomially_longer, attempts: ATTEMPTS do |job, error|
    job.give_up(error)
    raise error
  end

  def perform(allowed_drops: {}, operator_id: nil)
    @operator = operator_id && Operator.find_by(id: operator_id)
    feed = DebianTriage.feed
    if feed.url.nil?
      logger.info("[triage] no Debian Security Tracker configured (FLEET_DEBIAN_TRACKER_URL); refresh skipped")
      return nil
    end

    @source = feed.source
    # No active host reports a release in the table: nothing to download (an import that says so, and drops any
    # stored data).
    return DebianTriage::Import.new(origin: "feed", source: @source, operator: @operator).call(nil) if DebianTriage::Releases.in_use.empty?

    last = conditional_base
    download = feed.fetch(etag: last&.etag, last_modified: last&.last_modified)
    import = not_modified(last) if download.not_modified?
    if import.nil?
      if download.not_modified? # another import stored data since the request was made: the document is needed
        download.close!
        download = feed.fetch
      end
      import = import(download, allowed_drops)
    end
    logger.info("[triage] refresh from #{@source} #{import.state}: #{import.counts.except('releases').to_json}")
    import
  rescue Advisories::Feed::Unavailable, Advisories::Unreadable => e
    logger.warn("[triage] refresh failed (attempt #{executions} of #{ATTEMPTS}): #{e.message}")
    raise
  ensure
    download&.close!
  end

  # Called by retry_on once the retries are used up, and by bin/rails advisories:triage_refresh on its one
  # attempt. Returns the failed TriageImport.
  def give_up(error)
    reason = case error
    when Advisories::Feed::Unavailable, Advisories::Unreadable then error.message
    else "the refresh failed on the server (#{error.class.name}); see the server log"
    end
    logger.error("[triage] refresh failed after #{[ executions, 1 ].max} attempts: #{reason}")
    @operator ||= (id = arguments.first.to_h.symbolize_keys[:operator_id]) && Operator.find_by(id:)
    DebianTriage::Import.record_failure(origin: "feed", source: @source || DebianTriage.feed.source, reason:, operator: @operator)
  end

  private

  # The import whose validators may be sent, or nil: the latest import that stored or checked data, whatever its
  # origin or source, if it is a clean, complete success of the releases hosts now report from this feed. After a
  # file import, an import from another URL, a held-back import, or once a host reports another release, the same
  # document is needed again.
  def conditional_base
    latest = TriageImport.debian.where(state: %w[succeeded held_back]).order(finished_at: :desc, id: :desc).first
    return nil unless latest&.origin == "feed" && latest.source == @source && latest.state == "succeeded"
    return nil unless latest.counts["malformed"].to_i.zero? && latest.releases.sort == DebianTriage::Releases.in_use

    latest
  end

  def import(download, allowed_drops)
    DebianTriage::Import.new(origin: "feed", source: @source, operator: @operator, etag: download.etag, last_modified: download.last_modified, allowed_drops:)
                        .call(DebianTriage::Reader.new(download.file.path, name: File.basename(@source)))
  end

  # Records "not modified" as a refresh of last's releases, under the import lock, if last is still the latest stored
  # snapshot; nil if another import stored data meanwhile.
  def not_modified(last)
    TriageImport.transaction do
      DebianTriage::Import.lock!
      next nil unless conditional_base&.id == last.id

      now = Time.current
      TriageImport.create!(tracker: DebianTriage::TRACKER, origin: "feed", source: @source, operator: @operator, state: "succeeded", releases: last.releases,
                           counts: { "not_modified" => true }, etag: last.etag, last_modified: last.last_modified, started_at: now, finished_at: now)
    end
  end
end
