# One of an operator's recovery codes (P3-S09): an HMAC of the code, never the code, and when it was used. Each
# works once, wherever a 6-digit code is asked for (owner decision Q25).
class SecondFactorRecoveryCode < ApplicationRecord
  belongs_to :second_factor

  scope :unused, -> { where(used_at: nil) }
end
