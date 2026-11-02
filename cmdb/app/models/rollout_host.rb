# One host in a rollout and how its update is going (P1-UPDATES): pending (chosen, directive not sent yet),
# updating (directive sent), confirmed, failed, rolled_back, or unconfirmed (no result in time).
class RolloutHost < ApplicationRecord
  STATES = %w[pending updating confirmed failed rolled_back unconfirmed].freeze

  belongs_to :rollout
  belongs_to :host

  validates :state, inclusion: { in: STATES }
end
