require "rails_helper"

# Report load shedding (#200): lib/middleware/report_load_shedder.rb, FLEET_REPORT_MAX_IN_FLIGHT.
RSpec.describe ReportLoadShedder do
  describe "the middleware" do
    let(:gauge) { described_class::Gauge.new }
    let(:settings) { { max_in_flight: 2, retry_after: 30 } }
    let(:seen) { [] }
    # The downstream app records the in-flight count it saw; a nested call stands for a concurrent request.
    let(:inner) { ->(env) { seen << gauge.count; env["nested"] ? env["nested"].call : [ 200, {}, [ "ok" ] ] } }
    let(:shedder) { described_class.new(inner, gauge:, settings: -> { settings }, random: Random.new(1)) }

    def env_for(path, method: "POST", nested: nil)
      Rack::MockRequest.env_for(path, method:).merge("action_dispatch.request_id" => "req-1", "nested" => nested)
    end

    # Calls the shedder with `depth` reports in flight already, each still being handled.
    def call_nested(depth, path = "/api/v1/reports/packages")
      innermost = -> { shedder.call(env_for(path)) }
      depth.times.reduce(innermost) { |call, _| -> { shedder.call(env_for("/api/v1/reports/config", nested: call)) } }.call
    end

    it "passes reports through while fewer than the limit are in flight, counting each one" do
      status, _headers, body = call_nested(1)
      expect(status).to eq(200)
      expect(body).to eq([ "ok" ])
      expect(seen).to eq([ 1, 2 ])
      expect(gauge.count).to eq(0)
    end

    it "answers 503 overloaded with a spread Retry-After once the limit is in flight, and frees the slots after" do
      status, headers, body = call_nested(2)
      expect(status).to eq(503)
      expect(headers["retry-after"].to_i).to be_between(30, 60)
      error = JSON.parse(body.join)
      expect(error).to eq("error" => { "code" => "overloaded", "message" => AgentApi::Overloaded.default_message, "request_id" => "req-1" })
      expect(ApiContract.errors("error.response", "v1", error)).to eq([])
      expect(seen).to eq([ 1, 2 ])
      expect(gauge.count).to eq(0)
    end

    it "spreads Retry-After over [retry_after, 2 * retry_after] so a fleet turned away together returns apart" do
      waits = Array.new(200) { call_nested(2)[1]["retry-after"].to_i }
      expect(waits).to all(be_between(30, 60))
      expect(waits.uniq.size).to be > 20
    end

    it "never sheds heartbeats, task calls, or GETs, even with every slot taken" do
      2.times { gauge.enter(2) }
      expect(shedder.call(env_for("/api/v1/heartbeat")).first).to eq(200)
      expect(shedder.call(env_for("/api/v1/tasks/poll")).first).to eq(200)
      expect(shedder.call(env_for("/api/v1/reports/inventory", method: "GET")).first).to eq(200)
      expect(shedder.call(env_for("/api/v1/reports/inventory")).first).to eq(503)
    end

    it "is off with a limit of 0" do
      settings[:max_in_flight] = 0
      expect(call_nested(5).first).to eq(200)
      expect(seen).to all(eq(0))
    end

    it "frees its slot when the request raises" do
      failing = described_class.new(->(_env) { raise "boom" }, gauge:, settings: -> { settings })
      expect { failing.call(env_for("/api/v1/reports/inventory")) }.to raise_error("boom")
      expect(gauge.count).to eq(0)
    end

    it "logs each shed request with the path, the count, and the request id" do
      log = captured_log { call_nested(2) }
      expect(log).to match(%r{\[agent_api\] shed /api/v1/reports/packages: 2 reports in flight; retry after \d+s request_id=req-1})
    end
  end

  describe "in the app", type: :request do
    let!(:enrolled) { enrolled_host }
    let(:credential) { enrolled.last }
    let(:shedding) { Rails.configuration.x.agent_api }

    around do |example|
      before = shedding.report_shedding
      shedding.report_shedding = { max_in_flight: 1, retry_after: 30 }
      example.run
    ensure
      shedding.report_shedding = before
    end

    def inventory = inventory_example.merge("report_id" => SecureRandom.uuid)

    def heartbeat
      post_api("/api/v1/heartbeat", { schema_version: 1, agent_version: "0.1.0", hostname: "vm-01.example.lan", uptime_seconds: 42,
                                      agent_time: "2026-01-01T12:00:00Z" }, credential)
    end

    it "runs before the body guard, after the request id" do
      stack = Rails.application.middleware.map(&:klass)
      expect(stack.index(described_class)).to eq(stack.index(AgentApiRequestGuard) - 1)
      expect(stack.index(described_class)).to be > stack.index(ActionDispatch::RequestId)
    end

    it "answers a report with 503 and Retry-After while the process is at its limit, keeps heartbeats, and stores nothing" do
      described_class::GAUGE.enter(1)
      begin
        payload = inventory
        expect { post_api("/api/v1/reports/inventory", payload, credential) }.not_to change(InventoryReportReceipt, :count)
        expect_error(:service_unavailable, "overloaded")
        expect(response.headers["Retry-After"].to_i).to be_between(30, 60)

        heartbeat
        expect(response).to have_http_status(:ok)
      ensure
        described_class::GAUGE.leave
      end

      # The agent retries the same report later, and it is accepted.
      post_api("/api/v1/reports/inventory", payload, credential)
      expect(response).to have_http_status(:ok)
      expect(json).to eq("report_id" => payload["report_id"], "duplicate" => false)
    end

    it "sheds before authentication, so a 503 says nothing about the credential" do
      described_class::GAUGE.enter(1)
      post_api("/api/v1/reports/config", inventory, "not-a-credential")
      expect_error(:service_unavailable, "overloaded")
    ensure
      described_class::GAUGE.leave
    end
  end
end
