# One advisory import (P2-S10, P2-S13): a file, directory, or archive imported by hand, or a run of the
# scheduled feed refresh. Kept so the dashboard can say how fresh each ecosystem's data is, and what the last
# refresh did. The audit log records each one too.
#
# A file uploaded on the dashboard is imported in the background (P2-D06, owner decision on #129): its row is
# queued when the upload is stored, importing while AdvisoryUploadImportJob reads it, then succeeded or failed.
# finished_at is empty exactly while it is queued or importing.
class AdvisoryImport < ApplicationRecord
  STATES = %w[queued importing succeeded failed].freeze
  IN_PROGRESS = %w[queued importing].freeze
  ORIGINS = %w[feed file].freeze

  belongs_to :operator, optional: true

  validates :state, inclusion: { in: STATES }
  validates :origin, inclusion: { in: ORIGINS }

  scope :succeeded, -> { where(state: "succeeded") }
  scope :finished, -> { where.not(state: IN_PROGRESS) }
  scope :in_progress, -> { where(state: IN_PROGRESS) }
  # Imports that had data for ecosystem: matching treats it as having advisory data (P2-S11).
  scope :covering, ->(ecosystem) { where("? = ANY (ecosystems)", ecosystem) }

  def in_progress? = IN_PROGRESS.include?(state)
end
