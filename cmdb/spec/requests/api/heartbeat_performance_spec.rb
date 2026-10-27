require "rails_helper"

# NFR-3: heartbeat handling stays under 200 ms at the 95th percentile with 50 hosts. This measures the full
# request path in the test environment; P1-VERIFY repeats it with the simulator against a production-like
# server and a large snapshot table.
RSpec.describe "Heartbeat performance (NFR-3)", type: :request do
  it "keeps p95 under 200 ms across 50 hosts" do
    allow(AgentApi.config).to receive(:rate_limit).and_return(to: 1_000, within: 1.minute)
    hosts = Array.new(50) { |i| enrolled_host(hostname: "perf-#{i}.example.lan") }
    body = { schema_version: 1, agent_version: "0.1.0", hostname: nil, uptime_seconds: 1, agent_time: "2026-01-01T12:00:00Z" }.to_json
    hosts.each { |_, credential| post "/api/v1/heartbeat", params: body, headers: api_headers(credential) } # warm up

    timings = Array.new(5).flat_map do
      hosts.map do |_, credential|
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        post "/api/v1/heartbeat", params: body, headers: api_headers(credential)
        expect(response).to have_http_status(:ok)
        (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000
      end
    end
    p95 = timings.sort[(timings.size * 0.95).ceil - 1]
    expect(p95).to be < 200, "p95 was #{p95.round(1)} ms"
  end
end
