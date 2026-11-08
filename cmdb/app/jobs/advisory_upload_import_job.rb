# Imports an advisory file uploaded on the dashboard (P2-D06, owner decision on #129), so a large archive is
# never imported inside a web request. The controller stores the file (AdvisoryUpload) and its import, queued,
# in one transaction and enqueues this job; the result page refreshes itself until the import is done.
#
# - The import is marked importing, the file is written to a private temporary file for Advisories::Reader, and
#   Advisories::Import finishes the same row as succeeded, audited with the operator who uploaded it. What the
#   result page says about re-matching is stored on the row.
# - The file is read with the upload limits (Advisories::Reader::UPLOAD), and reading and storing it may take
#   TIME_LIMIT once the import lock is held (review of #129). A file that cannot be read at all, breaks a limit,
#   or runs past the time limit is an outcome, not a fault: the import is failed with the reason and the job
#   ends, with no retry. Waiting more than LOCK_WAIT for the lock (a feed refresh importing) is retried.
# - A full import is guarded (Advisories::Import, as every full import is): one that would withdraw too much of an
#   ecosystem is failed with the counts and its file kept, so the operator can confirm those counts on the
#   result page (DataSourcesController#confirm_withdrawals), which queues it again with them allowed.
# - Any other error is retried with backoff (ApplicationJob's schedule). After the last attempt the import is
#   failed with a reason, audited, and the error raised again, so the job shows on the failed-jobs page and in
#   /health like any other.
# - However the import ends, the stored file is deleted. A job that never runs, or is interrupted, leaves its
#   upload to AdvisoryUploadPruneJob, which deletes it and fails the import after AdvisoryUpload::LIFETIME.
class AdvisoryUploadImportJob < ApplicationJob
  queue_as :default

  # Reading and storing an upload within the limits takes well under a minute (about 2,000 records a second).
  TIME_LIMIT = 10.minutes
  LOCK_WAIT = 2.minutes

  retry_on StandardError, wait: :polynomially_longer, attempts: ATTEMPTS do |job, error|
    job.give_up(error)
    raise error
  end

  def perform(import_id)
    import = AdvisoryImport.find_by(id: import_id)
    return unless import&.in_progress? # done already (a retry after success), or failed by the prune job

    upload = AdvisoryUpload.without_data.find_by(advisory_import_id: import.id)
    return Advisories::Import.record_failure(import:, reason: "the uploaded file was no longer stored, so nothing was imported; upload it again") unless upload

    import.update!(state: "importing")
    Tempfile.create([ "advisory-upload-", File.extname(upload.filename) ], binmode: true) do |file|
      file.write(upload.read_data)
      file.flush
      reader = Advisories::Reader.new(file.path, name: upload.filename, limits: Advisories::Reader::UPLOAD)
      result = Advisories::Import.new(record: import, allowed_withdrawals: upload.allowed_withdrawals)
                                 .call(reader, time_limit: TIME_LIMIT.to_i, lock_timeout: LOCK_WAIT.to_i)
      import.update!(matching: matching(result.changed_packages))
    end
    remove_upload(import_id)
  rescue Advisories::Unreadable => e
    Advisories::Import.record_failure(import:, reason: e.message)
    remove_upload(import_id)
  rescue Advisories::Import::WithdrawalsRefused => e
    # The file is kept until it expires, for the operator's second confirmation.
    Advisories::Import.record_held_back(e, import:)
  rescue Advisories::Import::Abandoned
    remove_upload(import_id) # the prune job failed it meanwhile; nothing was written
  end

  # Called by retry_on once the retries are used up.
  def give_up(error)
    import_id = arguments.first
    import = AdvisoryImport.find_by(id: import_id)
    if import&.in_progress?
      logger.error("[advisories] upload import #{import_id} failed after #{executions} attempts: #{error.class.name}")
      Advisories::Import.record_failure(import:, reason: "the import failed on the server (#{error.class.name}) after #{executions} attempts; see the failed jobs page")
    end
    remove_upload(import_id)
  end

  private

  def remove_upload(import_id) = AdvisoryUpload.where(advisory_import_id: import_id).delete_all

  # How many changed source packages findings are matched again for, and on how many hosts in the fleet.
  def matching(changed_packages)
    sources = changed_packages.values.flatten.uniq
    hosts = sources.empty? ? 0 : HostPackage.joins(:host).merge(Host.in_fleet).where("COALESCE(host_packages.source, host_packages.name) IN (?)", sources).distinct.count(:host_id)
    { "packages" => sources.size, "hosts" => hosts }
  end
end
