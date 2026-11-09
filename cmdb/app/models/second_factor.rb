# An operator's TOTP authenticator (P3-S09, DEC-06): one per operator. The key is encrypted at rest with Active
# Record encryption (threat model C13), so the column holds only ciphertext; recovery codes are stored as HMACs.
# Changed only through SecondFactors (app/services/second_factors.rb), which audits each change.
class SecondFactor < ApplicationRecord
  belongs_to :operator
  has_many :recovery_codes, class_name: "SecondFactorRecoveryCode", dependent: :delete_all

  encrypts :secret

  validates :secret, :enrolled_at, presence: true

  def locked?(now = Time.current) = locked_until.present? && locked_until > now
end
