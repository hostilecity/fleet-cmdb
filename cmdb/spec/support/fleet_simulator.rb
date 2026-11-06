require Rails.root.join("lib/fleet_simulator").to_s

# Test doubles for the fleet simulator (P1-O04).
module FleetSimulatorHelpers
  # Sends the simulator's requests through the whole Rails stack in this process and thread, so they run inside
  # the example's transaction: the real routes, host separation, authentication, schemas, and controllers.
  class RackTransport
    attr_reader :requests

    def initialize
      @requests = []
    end

    def post_api(path, payload, credential: nil)
      env = { "CONTENT_TYPE" => "application/json", input: JSON.generate(payload), "HTTP_HOST" => HostSeparation.agent_host }
      env["HTTP_AUTHORIZATION"] = "Bearer #{credential}" if credential
      call(:post, path, env)
    end

    def get_dashboard(path, cookie:)
      call(:get, path, "HTTP_HOST" => HostSeparation.dashboard_host, "HTTP_COOKIE" => cookie)
    end

    private

    def call(method, path, env)
      @requests << [ method, path ]
      status, headers, body = Rails.application.call(Rack::MockRequest.env_for(path, method: method.to_s.upcase, "REMOTE_ADDR" => "192.0.2.250", **env))
      text = +""
      body.each { |chunk| text << chunk }
      body.close if body.respond_to?(:close)
      FleetSimulator::Response.new(status:, body: text, headers: headers.to_h.transform_keys(&:downcase), ms: 5.0)
    end
  end

  # A clock that moves only when slept on.
  class FakeClock
    attr_reader :now

    def initialize(now = Time.current)
      @now = now
      @monotonic = 0.0
    end

    def monotonic = @monotonic += 0.004

    def sleep(seconds)
      @now += seconds
    end

    def advance(seconds) = sleep(seconds)
  end

  def simulator_options(*argv) = FleetSimulator::Options.parse([ "--concurrency", "1", *argv ])
end

RSpec.configure do |config|
  config.include FleetSimulatorHelpers
end
