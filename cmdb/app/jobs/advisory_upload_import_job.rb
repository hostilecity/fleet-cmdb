# Imports an advisory file uploaded on the dashboard (P2-D06, owner decision on #129), so a large archive is
# never imported inside a web request. The controller stores the file (AdvisoryUpload) and its import, queued,
# in one transaction and enqueues this job; the result page refreshes itself until the import is done.
#
# - The import is marked importing, the file is written to a private temporary file for Advisories::Reader, and
#   Advisories::Import finishes the same row as succeeded, audited with the operator who uploaded it. What the
#   result page says about re-matching is stored on the row.
# - A file that cannot be read at all is an outcome, not a fault: the import is failed with the reason and the
#   job ends, with no retry.
# - Any other error is retried with backoff (ApplicationJob's schedule). After the last attempt the import is
#   failed with a reason, audited, and the error raised again, so the job shows on the failed-jobs page and in
#   /health like any other.
# - However the import ends, the stored file is deleted. A job that never runs, or is interrupted, leaves its
#   upload to AdvisoryUploadPruneJob, which deletes it and fails the import after AdvisoryUpload::LIFETIME.
class AdvisoryUploadImportJob < ApplicationJob
  queue_as :default

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
      result = Advisories::Import.new(record: import).call(Advisories::Reader.new(file.path, name: upload.filename))
      import.update!(matching: matching(result.changed_packages))
    end
    remove_upload(import_id)
  rescue Advisories::Unreadable => e
    Advisories::Import.record_failure(import:, reason: e.message)
    remove_upload(import_id)
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
