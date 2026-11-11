# The confirmation page's record of what the operator confirmed (P3-S08, owner decision Q13, threat model H10): a
# signed token in the page's form with a digest of the request (type, parameters, target), the hosts the page
# showed, the operator, when it was drawn, and a one-time id. On submit the server refuses the request if the token
# is missing or forged, belongs to another operator, is over MAX_AGE old, or was drawn for a different request; and
# TaskBatches refuses it if the hosts it resolves to now differ from the ones shown. The one-time id is stored on the
# batch, so the same page cannot create two batches.
#
# The token is signed, not encrypted: it holds only ids and a digest, nothing the operator could not see on the page.
module TaskConfirmation
  MAX_AGE = 30.minutes
  MAX_TOKEN_BYTES = 4.kilobytes
  REQUEST_KEYS = %w[type parameters target].freeze

  # status: :ok, :missing (no token), :invalid (forged, damaged, or another operator's), :expired, or :changed (drawn
  # for a different request). host_ids, nonce, and issued_at are set for a genuine token, whatever its status.
  Verified = Data.define(:status, :host_ids, :nonce, :issued_at) do
    def ok? = status == :ok
  end

  module_function

  def issue(request, host_ids, operator:, now: Time.current)
    verifier.generate({ "digest" => digest(request), "host_ids" => host_ids.sort, "operator_id" => operator.id,
                        "nonce" => SecureRandom.uuid, "issued_at" => now.to_i }, purpose: :task_confirmation)
  end

  def verify(token, request, operator:, now: Time.current)
    return refused(:missing) if token.blank?

    data = verifier.verified(token, purpose: :task_confirmation) if token.is_a?(String) && token.bytesize <= MAX_TOKEN_BYTES
    return refused(:invalid) unless data.is_a?(Hash) && data["operator_id"] == operator.id

    issued_at = Time.zone.at(data["issued_at"])
    status = if issued_at < now - MAX_AGE then :expired
    elsif !ActiveSupport::SecurityUtils.secure_compare(data["digest"], digest(request)) then :changed
    else :ok
    end
    Verified.new(status:, host_ids: data["host_ids"], nonce: data["nonce"], issued_at:)
  end

  # The SHA-256 of the request's type, parameters, and target as canonical JSON (keys sorted at every level).
  def digest(request) = Digest::SHA256.hexdigest(JSON.generate(canonical(request.slice(*REQUEST_KEYS))))

  def canonical(value)
    case value
    when Hash then value.keys.map(&:to_s).sort.to_h { |key| [ key, canonical(value[key]) ] }
    when Array then value.map { |item| canonical(item) }
    else value
    end
  end

  def refused(status) = Verified.new(status:, host_ids: nil, nonce: nil, issued_at: nil)

  def verifier = Rails.application.message_verifier("task_confirmation")

  private_class_method :canonical, :refused, :verifier
end
