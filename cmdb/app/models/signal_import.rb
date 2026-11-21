# One import of an exploitation signal (VT-SIGNALS, ADR 0032): CISA KEV or FIRST EPSS, from the scheduled refresh
# (origin feed), a file imported by hand (file), or the stored data deleted by bin/rails signals:kev_clear or
# signals:epss_reset (task, state cleared). Kept, as advisory and triage imports are, so freshness and each import's outcome can be shown; the
# audit log records each one too.
class SignalImport < ApplicationRecord
  SIGNALS = %w[kev epss].freeze
  ORIGINS = %w[feed file task].freeze
  # held_back: the file would have dropped too many stored entries, so nothing was stored. Not a failure: not
  # retried, and not a failed job. cleared: the stored data was deleted by an operator.
  STATES = %w[succeeded failed held_back cleared].freeze

  belongs_to :operator, optional: true

  validates :signal, inclusion: { in: SIGNALS }
  validates :origin, inclusion: { in: ORIGINS }
  validates :state, inclusion: { in: STATES }

  scope :kev, -> { where(signal: "kev") }
  scope :epss, -> { where(signal: "epss") }
  scope :succeeded, -> { where(state: "succeeded") }

  def not_modified? = counts["not_modified"] == true
end
