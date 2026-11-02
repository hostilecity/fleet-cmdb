# Makes the request id available to every log line of the request, including Rails' own "Started" line and
# lines logged before a controller runs (NFR-4, P1-S11). ActionDispatch::RequestId has already taken the id
# from X-Request-Id or made one and returns it in the response header; controllers and audit entries read the
# same value from Current. Lives outside the autoloaded lib/ because middleware is not reloadable.
class RequestContext
  def initialize(app)
    @app = app
  end

  def call(env)
    Current.request_id = env["action_dispatch.request_id"]
    @app.call(env)
  end
end
