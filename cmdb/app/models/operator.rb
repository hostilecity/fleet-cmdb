# A dashboard operator, keyed by Google account (FR-S.4, DEC-06). Records are created on first sign-in by an
# allowlisted, verified Google email; there is no other way to create one and no password anywhere.
class Operator < ApplicationRecord
  validates :google_uid, presence: true, uniqueness: true
  validates :email, presence: true, length: { maximum: 254 }

  def allowlisted? = OperatorAllowlistEntry.allowed?(email)

  def audit_actor_type = "operator"

  def display_name = name.presence || email
end
