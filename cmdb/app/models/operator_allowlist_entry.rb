# An email address allowed to sign in to the dashboard (FR-S.4, DEC-06). Managed from the command line
# (bin/rails operators:allow, operators:disallow); every change is audited. Removing an entry signs that
# operator out on their next request.
class OperatorAllowlistEntry < ApplicationRecord
  EMAIL_FORMAT = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/

  validates :email, presence: true, length: { maximum: 254 }, format: { with: EMAIL_FORMAT }, uniqueness: true

  def self.normalize(email) = email.to_s.strip.downcase

  def self.allowed?(email) = exists?(email: normalize(email))

  def self.allow!(email, actor:)
    transaction(requires_new: true) do
      entry = create!(email: normalize(email))
      Audit.record(actor:, action: Audit::Actions::OPERATOR_ALLOWED, target: entry, changes: { "email" => [ nil, entry.email ] })
      entry
    end
  end

  # Returns false when the email was not on the list.
  def self.disallow!(email, actor:)
    transaction(requires_new: true) do
      entry = lock.find_by(email: normalize(email)) or return false
      entry.destroy!
      Audit.record(actor:, action: Audit::Actions::OPERATOR_DISALLOWED, target: entry, changes: { "email" => [ entry.email, nil ] })
      true
    end
  end
end
