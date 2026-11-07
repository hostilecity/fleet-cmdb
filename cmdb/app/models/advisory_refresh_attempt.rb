# When an advisory feed refresh started (P2-S15, FR-2.4): an operator's "Refresh now" (manual, with the
# operator), a run of the schedule (scheduled), or bin/rails advisories:refresh (task). The newest row of any
# kind starts the manual refresh cool-down. Advisories::ManualRefresh is the only code that writes them.
class AdvisoryRefreshAttempt < ApplicationRecord
  KINDS = %w[manual scheduled task].freeze

  belongs_to :operator, optional: true

  validates :kind, inclusion: { in: KINDS }
end
