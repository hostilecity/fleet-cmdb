# One advisory import (P2-S10, P2-S13): a file, directory, or archive imported by hand, or a run of the
# scheduled feed refresh. Kept so the dashboard can say how fresh each ecosystem's data is, and what the last
# refresh did. The audit log records each one too.
class AdvisoryImport < ApplicationRecord
  STATES = %w[succeeded failed].freeze
  ORIGINS = %w[feed file].freeze

  belongs_to :operator, optional: true

  validates :state, inclusion: { in: STATES }
  validates :origin, inclusion: { in: ORIGINS }

  scope :succeeded, -> { where(state: "succeeded") }
  # Imports that had data for ecosystem: matching treats it as having advisory data (P2-S11).
  scope :covering, ->(ecosystem) { where("? = ANY (ecosystems)", ecosystem) }
end
