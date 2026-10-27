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

  def call
    claims = @auth&.dig("extra", "id_info") or raise Refused, "no verified ID token"
    uid = @auth["uid"].to_s
    raise Refused, "ID token subject does not match the account" unless uid.present? && claims["sub"].to_s == uid
    raise Refused, "email not verified by Google" unless [ true, "true" ].include?(claims["email_verified"])

    email = OperatorAllowlistEntry.normalize(claims["email"])
    raise Refused, "email not on the allowlist" unless OperatorAllowlistEntry.allowed?(email)

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
end
