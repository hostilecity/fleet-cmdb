# A single-use, expiring enrollment token (DEC-04, P1-S05). The plaintext is returned once, by
# EnrollmentToken.issue!, and never stored: only a SHA-256 digest is kept.
class EnrollmentToken < ApplicationRecord
  FORMAT = /\A[A-Za-z0-9_-]{32,128}\z/

  Issued = Data.define(:record, :plaintext) do
    def inspect = "#<EnrollmentToken::Issued expires_at=#{record.expires_at.iso8601} [FILTERED]>"
    alias_method :to_s, :inspect
  end

  belongs_to :host

  scope :redeemable, -> { where(redeemed_at: nil).where("expires_at > ?", Time.current) }

  def self.issue!(host:, ttl: Rails.configuration.x.enrollment.token_ttl)
    plaintext = SecureRandom.urlsafe_base64(32)
    record = create!(host:, token_digest: AgentApi.digest(plaintext), expires_at: ttl.from_now)
    Issued.new(record:, plaintext:)
  end

  # The host a plaintext token belongs to, read without locking so callers can lock the host first.
  def self.host_id_for(plaintext)
    return nil unless FORMAT.match?(plaintext.to_s)

    where(token_digest: AgentApi.digest(plaintext)).pick(:host_id)
  end

  # The token row for a plaintext token, locked FOR UPDATE so concurrent redemptions are serialised. Lock the
  # host first (lock order: host, then token), then check redeemable? after locking.
  def self.lock_for_redemption(plaintext)
    return nil unless FORMAT.match?(plaintext.to_s)

    lock.find_by(token_digest: AgentApi.digest(plaintext))
  end

  def redeemable?(now = Time.current) = redeemed_at.nil? && expires_at > now
end
