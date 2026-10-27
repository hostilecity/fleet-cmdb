require "ipaddr"

# Keeps the dashboard and the agent API on their own hostnames (DEC-05, P1-S13, FR-S.2):
#
# - The agent hostname serves /api/ and the health paths only.
# - The dashboard hostname serves everything else (dashboard, sign-in, OAuth), never /api/ or health.
# - localhost serves the health paths only, for the container health check; it is not published anywhere.
# - Any other host, or a path on the wrong host, gets an empty 404.
#
# X-Forwarded-Host, X-Forwarded-For, Client-IP, and Forwarded are removed unless the request comes directly
# from a configured trusted proxy, so a client can claim neither another hostname (Rails would otherwise
# prefer the header over Host) nor another client address (which keys the enrollment rate limit). This runs
# first in the middleware stack, before OmniAuth (which answers /auth/... itself) and before routing.
class HostSeparation
  API_PREFIX = "/api"
  HEALTH_PATHS = %w[/up /health].freeze
  LOCAL_HOSTS = %w[localhost 127.0.0.1 ::1].freeze
  # Headers only a trusted proxy may set. Rails reads X-Forwarded-For and Client-IP for request.remote_ip
  # (the enrollment rate-limit key) even when the peer itself is untrusted, and Rack reads Forwarded for the
  # host, so all of them are dropped from any other peer.
  SPOOFABLE_HEADERS = %w[HTTP_X_FORWARDED_HOST HTTP_X_FORWARDED_FOR HTTP_CLIENT_IP HTTP_FORWARDED].freeze
  NOT_FOUND = [ 404, { "content-type" => "text/plain; charset=utf-8", "content-length" => "0" }, [] ].freeze

  def self.config = Rails.configuration.x.fleet_hosts

  def self.dashboard_host = config.dashboard

  def self.agent_host = config.agent

  # "Host" or "host:port" or "[v6]:port" -> lowercase host without port or brackets.
  def self.normalize(value)
    host = value.to_s.split(",").last.to_s.strip.downcase
    if host.start_with?("[")
      host[1...host.index("]").to_i].to_s
    elsif host.count(":") == 1
      host.split(":").first.to_s
    else
      host
    end
  end

  def self.api_path?(path) = path == API_PREFIX || path.start_with?("#{API_PREFIX}/")

  def self.health_path?(path) = HEALTH_PATHS.include?(path)

  # Whether a request for path on host may be served at all.
  def self.allowed?(host, path)
    if host == agent_host then api_path?(path) || health_path?(path)
    elsif host == dashboard_host then !api_path?(path) && !health_path?(path)
    elsif LOCAL_HOSTS.include?(host) then health_path?(path)
    else false
    end
  end

  def self.trusted_proxy?(address)
    ip = IPAddr.new(address.to_s)
    config.trusted_proxies.any? { |range| range.include?(ip) }
  rescue IPAddr::Error
    false
  end

  def initialize(app)
    @app = app
  end

  def call(env)
    SPOOFABLE_HEADERS.each { |header| env.delete(header) } unless self.class.trusted_proxy?(env["REMOTE_ADDR"])
    host = self.class.normalize(env["HTTP_X_FORWARDED_HOST"].presence || env["HTTP_HOST"].presence || env["SERVER_NAME"])
    return NOT_FOUND.dup unless self.class.allowed?(host, env["PATH_INFO"].to_s)

    @app.call(env)
  end
end
