# One import of a release from GitHub (P1-RELEASES): queued by an operator, run by AgentReleaseImportJob, and
# kept so the Agents page can show how it went. The audit log records the outcome too.
class AgentReleaseImport < ApplicationRecord
  STATES = %w[queued running imported refused failed].freeze
  IN_FLIGHT = %w[queued running].freeze

  belongs_to :operator
  belongs_to :agent_release, optional: true

  validates :state, inclusion: { in: STATES }

  scope :in_flight, -> { where(state: IN_FLIGHT) }
  scope :recent, -> { order(created_at: :desc, id: :desc).limit(10) }

  def finished? = !IN_FLIGHT.include?(state)

  def finish!(state, reason: nil, release: nil)
    update!(state:, reason:, agent_release: release, finished_at: Time.current)
  end
end
