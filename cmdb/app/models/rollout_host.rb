# One host in a rollout and how its update is going (P1-UPDATES): pending (chosen, directive not sent yet),
# updating (directive sent), confirmed, failed, rolled_back, unconfirmed (no result in time), or restart_loop (its agent
# restarted more than the restart-loop limit within its window after the update, #251: counts as failed).
class RolloutHost < ApplicationRecord
  STATES = %w[pending updating confirmed failed rolled_back unconfirmed restart_loop].freeze

  belongs_to :rollout
  belongs_to :host

  validates :state, inclusion: { in: STATES }
end
