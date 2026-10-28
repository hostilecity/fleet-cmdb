# An installer's request to join the fleet (DEC-17, P1-ONBOARD, FR-S.1). Modelled on the OAuth device
# authorization grant (RFC 8628):
#
# - The installer holds the device code (a secret; only its digest is stored) and polls with it.
# - The operator matches the short user code shown in the terminal and on the approval page. It identifies
#   the request but grants nothing: approving needs a signed-in operator.
# - Requests expire (default 10 minutes). "Expired" is derived from expires_at rather than stored.
#
# A request is never a host: the host is created, or re-enrolled, only when the installer collects its
# credential (Onboarding::Collect). Start, approve, reject, and collect are the only ways to change one.
class OnboardingRequest < ApplicationRecord
  STATES = %w[open approved rejected collected].freeze
  # RFC 8628's suggested alphabet: consonants only, no vowels (no words), no 0/O or 1/I confusion.
  USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ".chars.freeze
  USER_CODE_FORMAT = /\A[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}\z/
  DEVICE_CODE_FORMAT = /\A[A-Za-z0-9_-]{43,128}\z/
  CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/

  Started = Data.define(:record, :device_code) do
    def inspect = "#<OnboardingRequest::Started id=#{record.id} [FILTERED]>"
    alias_method :to_s, :inspect
  end

  belongs_to :decided_by, class_name: "Operator", optional: true
  belongs_to :host, optional: true

  validates :state, inclusion: { in: STATES }
  validates :user_code, format: { with: USER_CODE_FORMAT }

  # Waiting for an operator and not expired.
  scope :awaiting, ->(now = Time.current) { where(state: "open").where("expires_at > ?", now) }

  def self.config = Rails.configuration.x.onboarding

  # The dashboard page where an operator enters a user code (P1-D07).
  def self.verification_uri
    base = config.dashboard_url || "https://#{Rails.configuration.x.fleet_hosts.dashboard}"
    "#{base.delete_suffix('/')}/onboard"
  end

  def self.find_by_device_code(device_code)
    return nil unless DEVICE_CODE_FORMAT.match?(device_code.to_s)

    find_by(device_code_digest: AgentApi.digest(device_code))
  end

  def self.find_awaiting_by_user_code(user_code, now: Time.current)
    code = user_code.to_s.upcase.delete("^A-Z")
    code = "#{code[0, 4]}-#{code[4, 4]}"
    USER_CODE_FORMAT.match?(code) ? awaiting(now).find_by(user_code: code) : nil
  end

  def self.generate_user_code
    letters = Array.new(8) { USER_CODE_ALPHABET[SecureRandom.random_number(USER_CODE_ALPHABET.size)] }.join
    "#{letters[0, 4]}-#{letters[4, 4]}"
  end

  # Text the VM reported, made safe to store and show: control characters removed, lengths capped.
  def self.clean(value, max)
    value&.to_s&.gsub(CONTROL_CHARACTERS, "")&.strip&.first(max).presence
  end

  def expired?(now = Time.current) = expires_at <= now

  def awaiting?(now = Time.current) = state == "open" && !expired?(now)

  def user_code_url = "#{self.class.verification_uri}/#{user_code}"

  def os_name = os.is_a?(Hash) ? os["pretty_name"] : nil
end
