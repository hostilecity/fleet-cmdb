# Guards every /api/ request before Rails sees its body (P1-S06, NFR-1):
#
# - Bodies over MAX_BODY_BYTES get 413 with the JSON error envelope without being read further or parsed.
#   Controllers apply tighter per-endpoint limits (Api::V1::BaseController.max_body_bytes).
# - Rails is told the body has no form parameters, so it never parses agent JSON itself and never writes
#   agent payloads to the log ("Parameters:"). Api::V1::BaseController reads and validates the raw body.
#
# Lives outside the autoloaded lib/agent_api because middleware is not reloadable.
class AgentApiRequestGuard
  PATH_PREFIX = "/api/"
  MAX_BODY_BYTES = 1.megabyte

  def initialize(app, max_body_bytes: MAX_BODY_BYTES)
    @app = app
    @max_body_bytes = max_body_bytes
  end

  def call(env)
    return @app.call(env) unless env["PATH_INFO"].to_s.start_with?(PATH_PREFIX)

    env["action_dispatch.request.request_parameters"] = {}
    return too_large(env) if env["CONTENT_LENGTH"].to_i > @max_body_bytes

    if (input = env["rack.input"])
      body = input.read(@max_body_bytes + 1).to_s
      return too_large(env) if body.bytesize > @max_body_bytes

      env["rack.input"] = StringIO.new(body)
      env["CONTENT_LENGTH"] = body.bytesize.to_s
    end
    @app.call(env)
  end

  private

  def too_large(env)
    error = { code: "payload_too_large", message: "The request body is too large.", request_id: env["action_dispatch.request_id"] }
    [ 413, { "content-type" => "application/json; charset=utf-8" }, [ { error: error.compact }.to_json ] ]
  end
end
