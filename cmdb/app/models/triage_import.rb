# One import of a distribution tracker's triage (P2-S16, ADR 0022): a run of the scheduled refresh, or a file
# imported by hand. Kept, as advisory imports are, so freshness and the last import's outcome can be shown;
# the audit log records each one too.
#
# releases: the releases whose data this import stored. A held-back import stored the releases that passed the
# truncation guard and kept the previous data of the others (counts["releases"] says which and why).
class TriageImport < ApplicationRecord
  # held_back: at least one release kept its previous data because the file would have dropped too many of its
  # entries. Not a failure: not retried, and not a failed job.
  STATES = %w[succeeded failed held_back].freeze
  ORIGINS = %w[feed file].freeze

  belongs_to :operator, optional: true

  validates :state, inclusion: { in: STATES }
  validates :origin, inclusion: { in: ORIGINS }

  scope :debian, -> { where(tracker: DebianTriage::TRACKER) }
  # Imports that stored data: their releases are current as of finished_at.
  scope :stored, -> { where(state: %w[succeeded held_back]) }
end
