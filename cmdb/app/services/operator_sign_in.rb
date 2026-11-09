# Turns a Google OAuth callback into a signed-in operator, or refuses it (FR-S.4, DEC-06, P1-S01).
#
# OmniAuth has already checked the OAuth `state` and exchanged the code over TLS; omniauth-google-oauth2
# has checked the ID token's issuer, audience, and expiry. Here the ID token must be present, its subject
# must match the account, and its email must be verified by Google and on the allowlist. Refused sign-ins
# create no record.
class OperatorSignIn
  class Refused < StandardError; end

  def self.call(auth) = new(auth).call

  def initialize(auth)
    @auth = auth
  end

  # A fresh Google sign-in for an already signed-in session (P3-S09, Q27): the same checks as signing in, plus the
  # account must be the session's own and the ID token newer than SecondFactors::FRESH_SIGN_IN_WINDOW. Marks the
  # session as freshly signed in; creates and changes nothing else. Raises Refused, or WrongAccount with the email
  # Google signed in.
  class WrongAccount < Refused
    attr_reader :email

    def initialize(email)
      @email = email
      super("a fresh sign-in was for another Google account")
    end
  end

  def self.reauthenticate(auth, operator_session, now: Time.current) = new(auth).reauthenticate(operator_session, now:)

  def call
    uid, email = verified_identity

    Operator.transaction(requires_new: true) do
      # Conflict-safe for two first sign-ins at once: the unique index decides, and the loser finds the
      # winner's row. Then lock it so the update and audit entry are serialised.
      operator = Operator.create_or_find_by!(google_uid: uid) { |new_operator| new_operator.email = email }
      operator.lock!
      operator.update!(email:, name: @auth.dig("info", "name").to_s.squish.truncate(255).presence, last_signed_in_at: Time.current)
      Audit.record(actor: operator, action: Audit::Actions::OPERATOR_SIGNED_IN, target: operator)
      operator
    end
  end

  def reauthenticate(operator_session, now:)
    uid, email = verified_identity
    raise WrongAccount, email unless uid == operator_session.operator.google_uid

    issued_at = Integer(@auth.dig("extra", "id_info", "iat"), exception: false)
    raise Refused, "ID token is not fresh" unless issued_at && Time.zone.at(issued_at).between?(now - SecondFactors::FRESH_SIGN_IN_WINDOW, now + 1.minute)

    operator_session.update!(google_authenticated_at: now)
  end

  private

  # [uid, normalised email] of a verified, allowlisted Google account, or raises Refused.
  def verified_identity
    claims = @auth&.dig("extra", "id_info") or raise Refused, "no verified ID token"
    uid = @auth["uid"].to_s
    raise Refused, "ID token subject does not match the account" unless uid.present? && claims["sub"].to_s == uid
    raise Refused, "email not verified by Google" unless [ true, "true" ].include?(claims["email_verified"])

    email = OperatorAllowlistEntry.normalize(claims["email"])
    raise Refused, "email not on the allowlist" unless OperatorAllowlistEntry.allowed?(email)

    [ uid, email ]
  end
end
