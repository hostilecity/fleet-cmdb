# An advisory file uploaded on the dashboard, kept until its import job has read it (P2-D06, owner decision on
# #129). At most MAX_BYTES (a check constraint bounds it too), tied to the operator who uploaded it and to its
# queued AdvisoryImport. AdvisoryUploadImportJob deletes it when the import ends, however it ends;
# AdvisoryUploadPruneJob deletes any left after expires_at and fails their imports. In the database rather than
# on disk, so whichever process or container runs the job can read it, it is written in the same transaction as
# its import, and nothing is left in a directory the web server could serve.
class AdvisoryUpload < ApplicationRecord
  MAX_BYTES = 64.megabytes
  # Long enough for the job's retries and a queue held up by a feed refresh; an upload not imported by then is
  # dropped and its import failed.
  LIFETIME = 1.hour
  # Uploads stored at once, so storage stays bounded however many are sent: at most 3 x 64 MiB.
  MAX_PENDING = 3

  belongs_to :advisory_import
  belongs_to :operator

  scope :expired, ->(now = Time.current) { where(expires_at: ..now) }
  # The file can be 64 MiB: rows are loaded without it, and the job reads it on its own.
  scope :without_data, -> { select(column_names - [ "data" ]) }

  def read_data = self.class.where(id:).pick(:data)
end
