# Removes uploaded advisory files that were never imported (P2-D06, owner decision on #129): an upload's job
# deletes its file however the import ends, so a file still stored after AdvisoryUpload::LIFETIME belongs to a
# job that never ran or was interrupted. Its import is failed with a reason, audited with the operator who
# uploaded it, and the file deleted. Scheduled every 10 minutes in config/recurring.yml.
class AdvisoryUploadPruneJob < ApplicationJob
  queue_as :default

  def perform(now: Time.current)
    stale = AdvisoryImport.in_progress.where(origin: "file", started_at: ..(now - AdvisoryUpload::LIFETIME))
    stale.find_each do |import|
      Advisories::Import.record_failure(import:, reason: "the import did not finish within #{AdvisoryUpload::LIFETIME.in_minutes.to_i} minutes of the upload " \
                                                         "(its job was interrupted or never ran), so nothing was imported; upload the file again")
    end
    AdvisoryUpload.expired(now).delete_all
  end
end
