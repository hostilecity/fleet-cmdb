# The outcome an agent reported for an update (POST /api/v1/update-results, P1-UPDATES): the host's update
# history. Written by Rollouts.record_result! only, and never changed.
class AgentUpdate < ApplicationRecord
  OUTCOMES = %w[succeeded failed rolled_back].freeze

  belongs_to :host
  belongs_to :rollout

  validates :outcome, inclusion: { in: OUTCOMES }

  def readonly? = persisted? || super
end
