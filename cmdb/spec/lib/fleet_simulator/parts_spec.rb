require "rails_helper"

RSpec.describe "fleet simulator parts (P1-O04)" do
  describe FleetSimulator::SimHost do
    it "names hosts in order and gives the behaviours to the last ones, so sim-001 is always well behaved" do
      hosts = described_class.build_all(6, counts: { stop: 1, hostile: 1, churn: 1, duplicates: 1 })
      expect(hosts.map(&:name)).to eq(%w[sim-001 sim-002 sim-003 sim-004 sim-005 sim-006])
      expect(hosts.map(&:behaviour)).to eq([ nil, nil, :stop, :hostile, :churn, :duplicates ])
      expect(hosts.map { |h| [ h.stop?, h.hostile?, h.churn?, h.duplicates? ] }[2..]).to eq([ [ true, false, false, false ], [ false, true, false, false ],
                                                                                           [ false, false, true, false ], [ false, false, false, true ] ])
    end

    it "uses example hostnames, documentation addresses, and a machine id that is the same on every run" do
      host = described_class.new(index: 251)
      expect([ host.hostname, host.ipv4, host.ipv6 ]).to eq([ "sim-251.example.lan", "198.51.100.1", "2001:db8::fb" ])
      expect(described_class.new(index: 1).ipv4).to eq("192.0.2.1")
      expect(described_class.new(index: 750).ipv4).to eq("203.0.113.250")
      expect(host.machine_id).to match(/\A\h{32}\z/).and eq(described_class.new(index: 251).machine_id)
    end

    it "goes silent from silent_at until resumed" do
      host = described_class.new(index: 1)
      now = Time.current
      expect(host.silent?(now)).to be(false)
      host.silent_at = now
      expect([ host.silent?(now - 1), host.silent?(now) ]).to eq([ false, true ])
      host.resume!
      expect(host.silent?(now)).to be(false)
    end
  end

  describe FleetSimulator::Payloads do
    let(:payloads) { described_class.new(agent_version: "0.1.0") }
    let(:now) { Time.utc(2026, 1, 1, 12) }

    it "builds requests that match the published contract" do
      host = FleetSimulator::SimHost.new(index: 3, now: now - 60)
      expect(ApiContract.errors("heartbeat.request", "v1", payloads.heartbeat(host, now:))).to eq([])
      expect(ApiContract.errors("inventory.request", "v1", payloads.inventory(host, now:))).to eq([])
      expect(ApiContract.errors("onboarding.request", "v1", payloads.onboarding(host))).to eq([])
      expect(ApiContract.errors("enroll.request", "v1", payloads.enroll(host, "EXAMPLE-token-0123456789-0123456789"))).to eq([])
      expect(payloads.heartbeat(host, now:)).to include("hostname" => "sim-003.example.lan", "uptime_seconds" => 60)
    end

    it "changes the kernel of a churning host on every report, and of any host when asked" do
      host = FleetSimulator::SimHost.new(index: 1, behaviour: :churn)
      kernels = Array.new(2) { payloads.inventory(host, now:)["kernel_version"] }
      steady = FleetSimulator::SimHost.new(index: 2)
      expect(kernels).to eq(%w[6.12.0-sim.1-amd64 6.12.0-sim.2-amd64])
      expect(payloads.inventory(steady, now:)["kernel_version"]).to eq(payloads.inventory(steady, now:)["kernel_version"])
      expect(payloads.inventory(steady, now:, change_stable: true)["kernel_version"]).to eq("6.12.0-sim.1-amd64")
    end

    it "puts hostile text in the free-text fields of a hostile host, within the schema" do
      report = payloads.inventory(FleetSimulator::SimHost.new(index: 1, behaviour: :hostile, now:), now:)
      expect(report.dig("os", "pretty_name")).to eq(described_class::HOSTILE)
      expect(report["cpu_model"]).to eq(described_class::HOSTILE)
      expect(ApiContract.errors("inventory.request", "v1", report)).to eq([])
    end
  end

  describe FleetSimulator::Stats do
    let(:stats) { described_class.new }

    it "summarises timings by nearest-rank percentile" do
      t = Time.current
      (1..100).each { |i| stats.record(kind: :heartbeat, host: "sim-001", status: i == 100 ? 500 : 200, ms: i, at: t + i) }
      expect(stats.summary(:heartbeat)).to eq(count: 100, errors: 1, p50: 50, p95: 95, p99: 99, max: 100)
      expect(stats.quarters(:heartbeat)).to include(first: include(max: 25), last: include(p50: 88))
      expect(stats.status_counts(:heartbeat)).to eq(200 => 99, 500 => 1)
      expect(stats.summary(:fleet_list)).to eq(count: 0, errors: 0, p50: nil, p95: nil, p99: nil, max: nil)
    end

    it "writes every sample as CSV, keeping notes to one field" do
      stats.record(kind: :inventory, host: "sim-001", status: 422, ms: 12.345, at: Time.utc(2026, 1, 1), note: "bad, very\nbad")
      expect(stats.to_csv).to eq("at,kind,host,status,ms,note\n2026-01-01T00:00:00.000Z,inventory,sim-001,422,12.35,bad; very bad\n")
    end
  end

  describe FleetSimulator::HttpTransport do
    let(:clock) { FleetSimulatorHelpers::FakeClock.new }
    let(:transport) { described_class.new(url: "http://127.0.0.1:3000", agent_host: "agent.localhost", dashboard_host: "localhost", clock:) }

    it "addresses the agent API and the dashboard by Host header over one connection address" do
      api = stub_request(:post, "http://127.0.0.1:3000/api/v1/heartbeat")
            .with(headers: { "Host" => "agent.localhost", "Authorization" => "Bearer key.secret", "Content-Type" => "application/json" }, body: { a: 1 }.to_json)
            .to_return(status: 429, body: "{}", headers: { "Retry-After" => "7" })
      page = stub_request(:get, "http://127.0.0.1:3000/").with(headers: { "Host" => "localhost", "Cookie" => "s=1" }).to_return(status: 200, body: "<html>")
      response = transport.post_api("/api/v1/heartbeat", { a: 1 }, credential: "key.secret")
      expect([ response.status, response.retry_after, response.success?, response.json, response.ms.round ]).to eq([ 429, 7, false, {}, 4 ])
      expect(transport.get_dashboard("/", cookie: "s=1")).to have_attributes(status: 200, body: "<html>", retry_after: nil)
      expect(api).to have_been_requested
      expect(page).to have_been_requested
    end

    it "reports a failed connection as status 0 and opens a new connection next time" do
      stub_request(:post, "http://127.0.0.1:3000/api/v1/enroll").to_raise(Errno::ECONNREFUSED).then.to_return(status: 201, body: "{}")
      expect(transport.post_api("/api/v1/enroll", {})).to have_attributes(status: 0, body: "Errno::ECONNREFUSED")
      expect(transport.post_api("/api/v1/enroll", {}).status).to eq(201)
    end
  end
end
