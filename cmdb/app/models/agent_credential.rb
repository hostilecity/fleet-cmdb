# A host's agent credential (FR-S.1, P1-S04). The plaintext `<key_id>.<secret>` is returned once, by
# AgentCredential.issue!, and never stored: only a SHA-256 digest of the secret is kept. Credentials are
# revoked, never deleted, and a host has at most one active credential.
class AgentCredential < ApplicationRecord
  STATES = %w[active revoked].freeze
  BEARER = /\ABearer ([A-Za-z0-9_-]{8,64})\.([A-Za-z0-9_-]{32,128})\z/
  # Compared against when the key id is unknown, so an unknown key takes as long as a wrong secret.
  UNKNOWN_KEY_DIGEST = AgentApi.digest("unknown key")
  # last_used_at is updated at most this often, so heartbeats do not each cost a write.
  LAST_USED_RESOLUTION = 5.minutes

  Issued = Data.define(:record, :plaintext) do
    def inspect = "#<AgentCredential::Issued key_id=#{record.key_id} [FILTERED]>"
    alias_method :to_s, :inspect
  end

  belongs_to :host

  validates :state, inclusion: { in: STATES }
  validates :key_id, format: { with: /\A[A-Za-z0-9_-]{8,64}\z/ }
  validates :machine_id, format: { with: /\A[0-9a-f]{32}\z/ }, allow_nil: true

  scope :active, -> { where(state: "active") }

  def self.issue!(host:, machine_id: nil)
    key_id = "fa_#{SecureRandom.alphanumeric(20)}"
    secret = SecureRandom.urlsafe_base64(32)
    record = create!(host:, key_id:, secret_digest: AgentApi.digest(secret), machine_id:)
    Issued.new(record:, plaintext: "#{key_id}.#{secret}")
  end

  # The active credential for an `Authorization: Bearer <key_id>.<secret>` header, or nil. Missing, malformed,
  # unknown, wrong, revoked, and retired-host credentials are indistinguishable to the caller.
  def self.authenticate(authorization)
    match = BEARER.match(authorization.to_s) or return nil

    key_id, secret = match.captures
    credential = includes(:host).find_by(key_id:)
    matches = ActiveSupport::SecurityUtils.secure_compare(AgentApi.digest(secret), credential&.secret_digest || UNKNOWN_KEY_DIGEST)
    credential if matches && credential.active? && !credential.host.retired?
  end

  def active? = state == "active"

  def revoke!
    update!(state: "revoked", revoked_at: Time.current) if active?
  end

  def record_use!(now = Time.current)
    update_column(:last_used_at, now) if last_used_at.nil? || last_used_at < now - LAST_USED_RESOLUTION
  end
end
