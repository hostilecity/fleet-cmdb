require "net/http"

module FleetSimulator
  Response = Data.define(:status, :body, :headers, :ms) do
    def json = JSON.parse(body.to_s)
    def success? = status.between?(200, 299)
    # Seconds to wait from a 429's Retry-After (DEC-08), or nil for any other answer.
    def retry_after = status == 429 ? [ headers["retry-after"].to_i, 1 ].max : nil
  end

  # Talks to a running server over HTTP, as agents and browsers do. Requests are addressed by Host header, so
  # one connection address serves both the agent hostname and the dashboard hostname (DEC-05, P1-S13). Each
  # thread keeps its own keep-alive connection, as each agent does. Timings cover the whole exchange, from
  # sending the request to reading the last byte of the body.
  class HttpTransport
    def initialize(url:, agent_host:, dashboard_host:, timeout: 15, clock: Clock.new)
      @uri = URI(url)
      @agent_host = agent_host
      @dashboard_host = dashboard_host
      @timeout = timeout
      @clock = clock
    end

    def post_api(path, payload, credential: nil)
      request = Net::HTTP::Post.new(path, "Content-Type" => "application/json", "Host" => @agent_host)
      request["Authorization"] = "Bearer #{credential}" if credential
      request.body = JSON.generate(payload)
      perform(request)
    end

    def get_dashboard(path, cookie:)
      perform(Net::HTTP::Get.new(path, "Host" => @dashboard_host, "Cookie" => cookie, "Accept" => "text/html"))
    end

    private

    def perform(request)
      started = @clock.monotonic
      response = connection.request(request)
      Response.new(status: response.code.to_i, body: response.body.to_s, headers: response.to_hash.transform_values(&:first),
                   ms: (@clock.monotonic - started) * 1000)
    rescue IOError, SystemCallError, Timeout::Error, Net::HTTPBadResponse, OpenSSL::SSL::SSLError => e
      drop_connection
      Response.new(status: 0, body: e.class.name, headers: {}, ms: (@clock.monotonic - started) * 1000)
    end

    def connections = Thread.current[:fleet_simulator_connections] ||= {}

    def connection
      connections[object_id] ||= Net::HTTP.new(@uri.host, @uri.port).tap do |http|
        http.use_ssl = @uri.scheme == "https"
        http.open_timeout = http.read_timeout = http.write_timeout = @timeout
        http.keep_alive_timeout = 30
        http.start
      end
    end

    def drop_connection
      connection = connections.delete(object_id)
      connection.finish if connection&.started?
    end
  end
end
