# Guards every /api/ request before Rails sees its body (P1-S06, NFR-1):
#
# - Bodies over MAX_BODY_BYTES get 413 with the JSON error envelope without being read further or parsed.
#   Controllers apply tighter per-endpoint limits (Api::V1::BaseController.max_body_bytes).
# - A path in UNCOMPRESSED_LIMITS takes a larger uncompressed body, up to the controller's own limit, so an
#   agent need not compress (package reports, P2-S08). A compressed body (any Content-Encoding but identity)
#   is still held to MAX_BODY_BYTES on the wire; the controller limits what it expands to.
# - Rails is told the body has no form parameters, so it never parses agent JSON itself and never writes
#   agent payloads to the log ("Parameters:"). Api::V1::BaseController reads and validates the raw body.
#
# Lives outside the autoloaded lib/agent_api because middleware is not reloadable.
class AgentApiRequestGuard
  PATH_PREFIX = "/api/"
  MAX_BODY_BYTES = 1.megabyte
  # Must match the controller's max_body_bytes for the path (spec/requests/api/request_guard_spec.rb checks).
  UNCOMPRESSED_LIMITS = { "/api/v1/reports/packages" => 4.megabytes }.freeze

  def initialize(app, max_body_bytes: MAX_BODY_BYTES, uncompressed_limits: UNCOMPRESSED_LIMITS)
    @app = app
    @max_body_bytes = max_body_bytes
    @uncompressed_limits = uncompressed_limits
  end

  def call(env)
    return @app.call(env) unless env["PATH_INFO"].to_s.start_with?(PATH_PREFIX)

    env["action_dispatch.request.request_parameters"] = {}
    limit = limit_for(env)
    return too_large(env) if env["CONTENT_LENGTH"].to_i > limit

    if (input = env["rack.input"])
      body = input.read(limit + 1).to_s
      return too_large(env) if body.bytesize > limit

      env["rack.input"] = StringIO.new(body)
      env["CONTENT_LENGTH"] = body.bytesize.to_s
    end
    @app.call(env)
  end

  private

  def limit_for(env)
    encoding = env["HTTP_CONTENT_ENCODING"].to_s.strip.downcase
    return @max_body_bytes unless encoding.empty? || encoding == "identity"

    @uncompressed_limits.fetch(env["PATH_INFO"], @max_body_bytes)
  end

  # The same status, code, and message as AgentApi::PayloadTooLarge, which controllers raise for their tighter
  # limits. Looked up on each call, since AgentApi is reloadable and this middleware is not.
  def too_large(env)
    refusal = AgentApi::PayloadTooLarge
    error = { code: refusal.code, message: refusal.default_message, request_id: env["action_dispatch.request_id"] }
    [ Rack::Utils.status_code(refusal.status), { "content-type" => "application/json; charset=utf-8" }, [ { error: error.compact }.to_json ] ]
  end
end
