# A signed-in dashboard session (P1-S01, NFR-1). The browser holds a random token in the encrypted session
# cookie; only its SHA-256 digest is stored. A session is valid until it is revoked (sign-out), goes idle,
# reaches its absolute lifetime, or its operator leaves the allowlist.
class OperatorSession < ApplicationRecord
  # last_seen_at is written at most this often, so idle timeouts are accurate to about a minute.
  LAST_SEEN_RESOLUTION = 1.minute

  belongs_to :operator

  # Returns [session, plaintext_token]. Also clears this operator's sessions that can no longer be used.
  def self.start!(operator, now: Time.current)
    where(operator:).where("revoked_at IS NOT NULL OR created_at < ?", now - absolute_timeout).delete_all
    token = SecureRandom.urlsafe_base64(32)
    [ create!(operator:, token_digest: AgentApi.digest(token), last_seen_at: now), token ]
  end

  # The live session for a token, or nil.
  def self.authenticate(token, now: Time.current)
    return nil if token.blank?

    session = includes(:operator).find_by(token_digest: AgentApi.digest(token.to_s))
    session if session&.live?(now) && session.operator.allowlisted?
  end

  # Re-reads a session already authenticated, for long-lived connections (ApplicationCable::Connection).
  def self.still_valid?(session, now: Time.current)
    current = includes(:operator).find_by(id: session.id)
    current.present? && current.live?(now) && current.operator.allowlisted?
  end

  def self.idle_timeout = Rails.configuration.x.sessions.idle_timeout

  def self.absolute_timeout = Rails.configuration.x.sessions.absolute_timeout

  def live?(now = Time.current)
    revoked_at.nil? && now - created_at <= self.class.absolute_timeout && now - last_seen_at <= self.class.idle_timeout
  end

  def record_activity!(now = Time.current)
    update_column(:last_seen_at, now) if last_seen_at < now - LAST_SEEN_RESOLUTION
  end

  def revoke!(now = Time.current)
    update!(revoked_at: now) if revoked_at.nil?
  end
end
