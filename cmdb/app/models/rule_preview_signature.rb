# Proves that Save saves the rule the operator previewed (P2-D06, owner decisions Q11 and Q12; review S1 of #130).
# The preview page signs the rule it previewed, as checked and normalised (CisRules.canonical_json, so key order does
# not matter), with the version an edit started from and the operator, and expires after TTL. Save rebuilds the rule
# from the submitted fields and is refused unless the signature names exactly that rule, base version, and operator:
# an edited hidden field, a form from another preview, or one left open too long shows the preview again instead.
module RulePreviewSignature
  TTL = 15.minutes
  PURPOSE = "rule_preview"

  module_function

  def generate(rule, base_version_id:, operator:) = verifier.generate(payload(rule, base_version_id, operator), expires_in: TTL, purpose: PURPOSE)

  # Whether signature was made by generate for this rule, base version, and operator, and has not expired.
  def valid?(signature, rule, base_version_id:, operator:)
    return false unless signature.is_a?(String) && signature.present?

    verifier.verified(signature, purpose: PURPOSE) == payload(rule, base_version_id, operator) # nil when tampered with or expired
  end

  def payload(rule, base_version_id, operator) = [ CisRules.canonical_json(rule), base_version_id&.to_i, operator.id ]

  def verifier = Rails.application.message_verifier(PURPOSE)

  private_class_method :payload, :verifier
end
