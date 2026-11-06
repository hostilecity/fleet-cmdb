# One vulnerability advisory as last imported (P2-S10, FR-2.4, DEC-11): an OSV record, kept at its newest
# modified version. Withdrawn advisories are kept and marked, never deleted, so the findings they produced
# resolve with a reason instead of disappearing (P2-S11).
class Advisory < ApplicationRecord
  SEVERITIES = %w[critical high medium low unknown].freeze

  has_many :packages, class_name: "AdvisoryPackage", dependent: :delete_all

  validates :severity, inclusion: { in: SEVERITIES }

  scope :current, -> { where(withdrawn_at: nil) }

  def withdrawn? = withdrawn_at.present?
end
