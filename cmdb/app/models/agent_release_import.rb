# One import of a release from GitHub (P1-RELEASES): queued by an operator, run by AgentReleaseImportJob, and
# kept so the Agents page can show how it went. The audit log records the outcome too.
class AgentReleaseImport < ApplicationRecord
  STATES = %w[queued running imported refused failed].freeze
  IN_FLIGHT = %w[queued running].freeze

  belongs_to :operator
  belongs_to :agent_release, optional: true

  # An in-flight import that has not moved for this long has stopped: its worker died (out of memory, a deploy,
  # a lost node) without running the job's own error handling. The job updates the row at the start of each
  # attempt, and an attempt is bounded (Releases::Github::DEADLINE per download, plus the retry backoff), so
  # a live import never goes this long untouched (review of #74).
  STALE_AFTER = 30.minutes
  STOPPED = "The import stopped without finishing: no progress for #{STALE_AFTER.in_minutes.to_i} minutes.".freeze

  validates :state, inclusion: { in: STATES }

  scope :in_flight, -> { where(state: IN_FLIGHT) }
  scope :recent, -> { order(created_at: :desc, id: :desc).limit(10) }
  scope :stale, -> { in_flight.where(updated_at: ...STALE_AFTER.ago) }

  # Closes the stopped imports of version as failed, audited, so the version can be imported again. Without
  # this, one dead worker would block that version for good (one in-flight import per version).
  def self.close_stale!(version)
    stale.where(version:).find_each do |import|
      Releases::Import.record_failure(operator: import.operator, source: "github", version:, reason: STOPPED) do
        import.finish!("failed", reason: STOPPED)
      end
    end
  end

  def finished? = !IN_FLIGHT.include?(state)

  # Finishes the import unless something else already has (a stale import closed while its worker was in
  # fact still running finishes once, as failed).
  def finish!(state, reason: nil, release: nil)
    with_lock do
      finished? ? false : update!(state:, reason:, agent_release: release, finished_at: Time.current)
    end
  end
end
