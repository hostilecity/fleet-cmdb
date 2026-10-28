require "rails_helper"

# P1-S13, DEC-05: the dashboard and the agent API answer only on their own hostnames, and a forged Host or
# X-Forwarded-Host cannot cross the boundary.
RSpec.describe "Host-based separation", type: :request do
  UNTRUSTED = "203.0.113.9".freeze # a client reaching the app directly, not through a trusted proxy

  def request_as(method, path, host:, forwarded_host: nil, remote_addr: UNTRUSTED)
    host! host
    headers = forwarded_host ? { "X-Forwarded-Host" => forwarded_host } : {}
    public_send(method, path, headers:, env: { "REMOTE_ADDR" => remote_addr })
  end

  def expect_empty_404
    expect(response).to have_http_status(:not_found)
    expect(response.body).to be_empty
  end

  describe "the agent API" do
    it "answers on the agent host" do
      request_as(:post, "/api/v1/enroll", host: agent_host)
      expect(response.parsed_body.dig("error", "code")).to eq("validation_failed") # reached the endpoint
    end

    it "returns 404 on the dashboard host, for every /api path" do
      %w[/api /api/v1 /api/v1/enroll /api/v1/heartbeat /api/v2/anything].each do |path|
        request_as(:post, path, host: dashboard_host)
        expect_empty_404
      end
    end
  end

  describe "the dashboard" do
    it "answers on the dashboard host" do
      request_as(:get, "/sign_in", host: dashboard_host)
      expect(response).to have_http_status(:ok)
    end

    it "returns 404 on the agent host for every dashboard path, including sign-in and OAuth" do
      [ [ :get, "/" ], [ :get, "/sign_in" ], [ :post, "/auth/google_oauth2" ], [ :get, "/auth/google_oauth2/callback" ],
        [ :get, "/auth/failure" ], [ :delete, "/sign_out" ], [ :get, "/cable" ], [ :get, "/assets/application.css" ] ].each do |method, path|
        request_as(method, path, host: agent_host)
        expect_empty_404
      end
    end
  end

  describe "health checks" do
    it "answer on the agent host and localhost, never the dashboard host (the tunnel)" do
      request_as(:get, "/up", host: agent_host)
      expect(response).to have_http_status(:ok)
      request_as(:get, "/up", host: "localhost", remote_addr: "127.0.0.1")
      expect(response).to have_http_status(:ok)
      request_as(:get, "/up", host: dashboard_host)
      expect_empty_404
    end

    it "is the only thing localhost serves" do
      request_as(:get, "/sign_in", host: "localhost", remote_addr: "127.0.0.1")
      expect_empty_404
      request_as(:post, "/api/v1/enroll", host: "127.0.0.1", remote_addr: "127.0.0.1")
      expect_empty_404
    end
  end

  it "returns an empty 404 for any other host" do
    [ "evil.example", "fleet.example.lan.evil.example", "", "agent.fleet.example.lan.example" ].each do |host|
      request_as(:get, "/sign_in", host:)
      expect_empty_404
      request_as(:post, "/api/v1/enroll", host:)
      expect_empty_404
    end
  end

  it "accepts hostnames in any case and with a port" do
    request_as(:get, "/sign_in", host: "#{dashboard_host.upcase}:443")
    expect(response).to have_http_status(:ok)
  end

  describe "forged headers" do
    it "ignores X-Forwarded-Host from an untrusted client in both directions" do
      request_as(:post, "/api/v1/enroll", host: dashboard_host, forwarded_host: agent_host)
      expect_empty_404
      request_as(:get, "/sign_in", host: agent_host, forwarded_host: dashboard_host)
      expect_empty_404
    end

    it "ignores a comma-separated X-Forwarded-Host chain from an untrusted client" do
      request_as(:post, "/api/v1/enroll", host: dashboard_host, forwarded_host: "#{dashboard_host}, #{agent_host}")
      expect_empty_404
    end

    it "honours X-Forwarded-Host only from a trusted proxy" do
      request_as(:get, "/sign_in", host: "rails:80", forwarded_host: dashboard_host, remote_addr: "127.0.0.1")
      expect(response).to have_http_status(:ok)
      request_as(:get, "/sign_in", host: "rails:80", forwarded_host: dashboard_host)
      expect_empty_404
    end

    it "ignores spoofed client addresses from an untrusted peer, so the enrollment rate limit holds" do
      limit = AgentApi.config.enroll_rate_limit[:to]
      body = { schema_version: 1, agent_version: "0.1.0", token: "EXAMPLE-unknown-token-0000000000000000000000", hostname: nil, machine_id: nil }.to_json
      host! agent_host
      (limit + 1).times do |i|
        post "/api/v1/enroll", params: body,
             headers: { "CONTENT_TYPE" => "application/json", "X-Forwarded-For" => "198.51.100.#{i}", "Client-IP" => "198.51.100.#{i}",
                        "Forwarded" => "for=198.51.100.#{i}" },
             env: { "REMOTE_ADDR" => UNTRUSTED }
      end
      expect(response).to have_http_status(:too_many_requests)
    end

    it "uses the client address a trusted proxy forwards" do
      limit = AgentApi.config.enroll_rate_limit[:to]
      body = { schema_version: 1, agent_version: "0.1.0", token: "EXAMPLE-unknown-token-0000000000000000000000", hostname: nil, machine_id: nil }.to_json
      host! agent_host
      (limit + 1).times do |i|
        post "/api/v1/enroll", params: body, headers: { "CONTENT_TYPE" => "application/json", "X-Forwarded-For" => "198.51.100.#{i}" },
             env: { "REMOTE_ADDR" => "127.0.0.1" }
      end
      expect(response).to have_http_status(:gone) # each agent has its own bucket
    end

    it "keeps a trusted proxy's forwarded host on its side of the boundary" do
      request_as(:post, "/api/v1/enroll", host: agent_host, forwarded_host: dashboard_host, remote_addr: "127.0.0.1")
      expect_empty_404
    end
  end

  describe "route constraints (second line of defence)" do
    it "constrains every route to a host" do
      unconstrained = Rails.application.routes.routes.reject do |route|
        route.constraints.any? || route.path.requirements.any? || route.app.respond_to?(:constraints)
      end
      expect(unconstrained.map { |r| r.path.spec.to_s }).to eq([])
    end

    it "does not route /api on the dashboard host even if the middleware is bypassed" do
      env = Rack::MockRequest.env_for("http://#{dashboard_host}/api/v1/enroll", method: "POST")
      status, = Rails.application.routes.call(env)
      expect(status).to eq(404)
    end

    it "does not route the dashboard on the agent host even if the middleware is bypassed" do
      %w[/sign_in / /settings /cable].each do |path|
        env = Rack::MockRequest.env_for("http://#{agent_host}#{path}")
        status, = Rails.application.routes.call(env)
        expect(status).to eq(404), path
      end
    end
  end
end

RSpec.describe HostSeparation do
  it "normalises Host header forms" do
    expect(described_class.normalize("Fleet.Example.LAN:443")).to eq("fleet.example.lan")
    expect(described_class.normalize("[::1]:3000")).to eq("::1")
    expect(described_class.normalize("::1")).to eq("::1")
    expect(described_class.normalize("a.example, b.example")).to eq("b.example")
    expect(described_class.normalize(nil)).to eq("")
  end

  it "drops proxy-only headers from untrusted peers and keeps them from trusted ones" do
    seen = nil
    app = described_class.new(->(env) { seen = env.slice(*described_class::SPOOFABLE_HEADERS); [ 200, {}, [] ] })
    headers = { "HTTP_X_FORWARDED_HOST" => "x", "HTTP_X_FORWARDED_FOR" => "198.51.100.1", "HTTP_CLIENT_IP" => "198.51.100.1", "HTTP_FORWARDED" => "for=198.51.100.1" }
    app.call(Rack::MockRequest.env_for("http://#{HostSeparation.agent_host}/up", "REMOTE_ADDR" => "203.0.113.9", **headers))
    expect(seen).to eq({})
    app.call(Rack::MockRequest.env_for("http://#{HostSeparation.agent_host}/up", "REMOTE_ADDR" => "127.0.0.1",
                                       "HTTP_X_FORWARDED_FOR" => "198.51.100.1", "HTTP_FORWARDED" => "for=198.51.100.1"))
    expect(seen).to eq("HTTP_X_FORWARDED_FOR" => "198.51.100.1", "HTTP_FORWARDED" => "for=198.51.100.1")
  end

  it "trusts only configured proxies" do
    expect(described_class.trusted_proxy?("127.0.0.1")).to be(true)
    expect(described_class.trusted_proxy?("203.0.113.9")).to be(false)
    expect(described_class.trusted_proxy?("not an ip")).to be(false)
  end
end
