# Sheds agent report load before Rails does any work for it (#200, P-16 of the performance assessment).
#
# The signal is simple and per process: report requests in flight (POST /api/v1/reports/inventory, config, and
# packages). When FLEET_REPORT_MAX_IN_FLIGHT are already being handled, another report is answered at once with
# 503 overloaded and a Retry-After of FLEET_REPORT_RETRY_AFTER_SECONDS to twice that, chosen at random so a fleet
# turned away together does not come back together. The agent keeps the report (same report_id) and waits at
# least that long (agent/src/retry.rs). Heartbeats, task calls, and everything else are never shed, so hosts stay
# online and the threads that are left serve them. A limit below the Puma thread count (RAILS_MAX_THREADS) keeps
# that many threads free for heartbeats. 0, the default, turns shedding off.
#
# Runs before AgentApiRequestGuard, so a shed report is not copied or parsed, and before authentication: a 503
# says nothing about the credential. Settings are read on each request from config.x.agent_api.report_shedding
# (config/initializers/agent_api.rb), since this middleware is not reloadable.
class ReportLoadShedder
  PATHS = %w[/api/v1/reports/inventory /api/v1/reports/config /api/v1/reports/packages].freeze

  # Reports in flight in this process. One per process, shared by its threads.
  class Gauge
    def initialize
      @lock = Mutex.new
      @count = 0
    end

    def count = @lock.synchronize { @count }

    # Takes a slot unless limit are taken; returns whether it did.
    def enter(limit)
      @lock.synchronize do
        return false if @count >= limit

        @count += 1
        true
      end
    end

    def leave = @lock.synchronize { @count -= 1 }
  end

  GAUGE = Gauge.new

  def initialize(app, gauge: GAUGE, settings: -> { Rails.configuration.x.agent_api.report_shedding }, random: Random.new)
    @app = app
    @gauge = gauge
    @settings = settings
    @random = random
  end

  def call(env)
    return @app.call(env) unless env["REQUEST_METHOD"] == "POST" && PATHS.include?(env["PATH_INFO"])

    settings = @settings.call
    limit = settings[:max_in_flight].to_i
    return @app.call(env) unless limit.positive?
    return overloaded(env, settings[:retry_after].to_i) unless @gauge.enter(limit)

    begin
      @app.call(env)
    ensure
      @gauge.leave
    end
  end

  private

  # The status, code, and message of AgentApi::Overloaded, looked up on each call since AgentApi is reloadable.
  def overloaded(env, retry_after)
    refusal = AgentApi::Overloaded
    request_id = env["action_dispatch.request_id"]
    wait = retry_after + @random.rand(0..retry_after)
    Rails.logger.warn("[agent_api] shed #{env['PATH_INFO']}: #{@gauge.count} reports in flight; retry after #{wait}s request_id=#{request_id}")
    error = { code: refusal.code, message: refusal.default_message, request_id: }
    [ Rack::Utils.status_code(refusal.status), { "content-type" => "application/json; charset=utf-8", "retry-after" => wait.to_s },
      [ { error: error.compact }.to_json ] ]
  end
end
