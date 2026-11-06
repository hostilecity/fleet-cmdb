require "rails_helper"

# The simulator against the real application, in process (FleetSimulatorHelpers::RackTransport): enrollment,
# reporting, the misbehaving hosts, the fleet list probe, and the liveness check (P1-O04).
RSpec.describe "fleet simulator against the agent API (P1-O04)" do
  let(:transport) { FleetSimulatorHelpers::RackTransport.new }
  let(:clock) { FleetSimulatorHelpers::FakeClock.new }
  let(:payloads) { FleetSimulator::Payloads.new(agent_version: "0.1.0") }
  let(:state_file) { Rails.root.join("tmp/fleet_simulator/spec-#{SecureRandom.hex(4)}.json") }
  let(:out) { StringIO.new }
  let(:stats) { FleetSimulator::Stats.new }

  after { FileUtils.rm_f(state_file) }

  def enroller(via: "token", transport: self.transport)
    FleetSimulator::Enroller.new(transport:, payloads:, via:, clock:, out:, state_file:)
  end

  def enrolled(count, via: "token", **counts)
    enroller(via:).enroll_all(FleetSimulator::SimHost.build_all(count, counts:, now: clock.now))
  end

  def runner(hosts, *argv, transport: self.transport, probe: nil)
    FleetSimulator::Runner.new(hosts:, transport:, payloads:, stats:, options: simulator_options(*argv), clock:, probe:)
  end

  describe FleetSimulator::Enroller do
    it "registers hosts and redeems their tokens at the enroll endpoint, keeping the credentials privately" do
      hosts = enrolled(2)
      expect(Host.where(name: %w[sim-001 sim-002]).pluck(:enrollment_state, :tags, :hostname))
        .to eq([ [ "active", [ "simulator" ], "sim-001.example.lan" ], [ "active", [ "simulator" ], "sim-002.example.lan" ] ])
      expect(hosts.map(&:host_id)).to eq(Host.where(name: %w[sim-001 sim-002]).order(:name).ids)
      expect(JSON.parse(state_file.read)).to eq(hosts.to_h { |h| [ h.name, h.credential ] })
      expect(state_file.stat.mode & 0o777).to eq(0o600)
    end

    it "reuses saved credentials the server still accepts, and re-enrolls the hosts whose credential it refuses" do
      first = enrolled(2)
      Host.find(first.last.host_id).revoke!(actor: Audit::SYSTEM)
      again = enrolled(2)
      expect(again.first.credential).to eq(first.first.credential)
      expect(again.last.credential).not_to eq(first.last.credential)
      expect(Host.find(first.last.host_id).enrollment_state).to eq("active")
      expect(Host.where(name: "sim-002").count).to eq(1)
    end

    it "onboards hosts through the installer's flow, approved by the simulator's operator" do
      hosts = enrolled(1, via: "onboarding")
      request = OnboardingRequest.order(:id).last
      expect([ request.state, request.decided_by.email, Host.find(hosts.first.host_id).name ]).to eq([ "collected", "simulator@example.com", "sim-001" ])
      expect(transport.requests.map(&:last)).to eq(%w[/api/v1/onboarding /api/v1/onboarding/token])

      FileUtils.rm_f(state_file) # forgotten credential: the same host is re-enrolled through onboarding
      enrolled(1, via: "onboarding")
      expect(Host.where(name: "sim-001").pluck(:enrollment_state)).to eq([ "active" ])
    end

    it "waits out rate limits as an agent would" do
      limited = Class.new(SimpleDelegator) do
        def post_api(path, payload, **options)
          return FleetSimulator::Response.new(status: 429, body: "{}", headers: { "retry-after" => "30" }, ms: 1) if (@limited = !@limited)

          __getobj__.post_api(path, payload, **options)
        end
      end
      before = clock.now
      enroller(transport: limited.new(transport)).enroll_all(FleetSimulator::SimHost.build_all(1))
      expect(clock.now - before).to eq(30)
      expect(out.string).to include("rate-limited; waiting 30s", "FLEET_ENROLL_RATE_LIMIT_PER_MINUTE")
    end

    it "stops with the server's answer when enrollment fails" do
      refusing = Class.new { def post_api(*, **) = FleetSimulator::Response.new(status: 422, body: '{"error":"no"}', headers: {}, ms: 1) }
      expect { enroller(transport: refusing.new).enroll_all(FleetSimulator::SimHost.build_all(1)) }
        .to raise_error(FleetSimulator::Enroller::Failed, /sim-001: enroll answered 422: \{"error":"no"\}/)
    end
  end

  describe FleetSimulator::Runner do
    it "sends the startup report and heartbeat, then heartbeats on the interval, and the server records them" do
      hosts = enrolled(1)
      run = runner(hosts, "--time-scale", "60") # heartbeat every second, inventory every 15 s
      run.start(clock.now)
      clock.advance(1.1) # past the first heartbeat, whatever the spread
      expect(run.step(clock.now)).to eq(1) # the startup report
      expect(run.step(clock.now)).to eq(1) # and the startup heartbeat straight after
      expect(run.step(clock.now)).to eq(0)
      clock.advance(1.2)
      run.step(clock.now)
      expect(stats.status_counts(:heartbeat)).to eq(200 => 2)
      expect(stats.status_counts(:inventory)).to eq(200 => 1)
      expect(Host.find(hosts.first.host_id)).to have_attributes(liveness_status: "online", agent_version: "0.1.0")
      expect(HostInventory.find_by!(host_id: hosts.first.host_id).stable).to include("hostname" => "sim-001.example.lan")
    end

    it "makes each behaviour happen: silence, hostile text, churning snapshots, and recognised duplicates" do
      hosts = enrolled(4, stop: 1, hostile: 1, churn: 1)
      hosts.first.instance_variable_set(:@behaviour, :duplicates)
      # A report and a heartbeat every second; the stopping host goes silent halfway, at 2 s. Few enough requests
      # for the test environment's rate limit of 10 a minute per credential.
      run = runner(hosts, "--time-scale", "900", "--heartbeat-seconds", "900", "--duration", "4")
      run.start(clock.now)
      3.times do
        clock.advance(1)
        2.times { run.step(clock.now) }
      end
      by_host = stats.of(:inventory).group_by(&:host).transform_values(&:size)
      expect(by_host["sim-002"]).to be < by_host["sim-001"] # sim-002 stopped halfway
      expect(stats.of(:duplicate).map(&:note).uniq).to eq([ "duplicate" ])
      expect(InventorySnapshot.where(host_id: hosts[3].host_id).count).to eq(by_host["sim-004"]) # churn: one snapshot per report
      expect(InventorySnapshot.where(host_id: hosts[0].host_id).count).to eq(1)
      expect(HostInventory.find_by!(host_id: hosts[2].host_id).stable.dig("os", "pretty_name")).to eq(FleetSimulator::Payloads::HOSTILE)
      expect(stats.summary(:inventory)[:errors] + stats.summary(:heartbeat)[:errors]).to eq(0)
    end

    it "seeds snapshots through the API before the run, waiting out rate limits" do
      hosts = enrolled(2)
      limited = Class.new(SimpleDelegator) do
        def post_api(path, payload, **options)
          return FleetSimulator::Response.new(status: 429, body: "{}", headers: { "retry-after" => "5" }, ms: 1) if (@limited = !@limited)

          __getobj__.post_api(path, payload, **options)
        end
      end
      runner(hosts, transport: limited.new(transport)).seed_snapshots(2)
      expect(InventorySnapshot.where(host_id: hosts.map(&:host_id)).group(:host_id).count.values).to eq([ 2, 2 ])
      expect(stats.status_counts(:seed)).to eq(200 => 4)
    end

    it "adopts the intervals the server asks for (ADR 0019), scaled like its own" do
      hosts = enrolled(1)
      Setting.update_agent_intervals!(heartbeat_seconds: 120, inventory_seconds: 1800, actor: Audit::SYSTEM)
      run = runner(hosts, "--time-scale", "2")
      run.start(clock.now)
      clock.advance(31)
      2.times { run.step(clock.now) }
      expect([ hosts.first.heartbeat_interval, hosts.first.inventory_interval ]).to eq([ 60, 900 ])
    end

    it "backs off for the Retry-After of a rate-limited heartbeat and notes refusals" do
      host = FleetSimulator::SimHost.build_all(1).first.tap { |h| h.credential = "key.secret" }
      busy = Class.new { def post_api(*, **) = FleetSimulator::Response.new(status: 429, body: '{"error":{"code":"rate_limited"}}', headers: { "retry-after" => "45" }, ms: 1) }
      run = runner([ host ], transport: busy.new)
      run.start(clock.now)
      host.next_inventory_at = clock.now + 3600
      clock.advance(61)
      run.step(clock.now)
      expect(host.next_heartbeat_at).to eq(clock.now + 45)
      expect(stats.of(:heartbeat).first.note).to include("rate_limited")
    end

    it "runs requests on a pool of workers until the deadline, then waits for those in flight" do
      hosts = FleetSimulator::SimHost.build_all(3).each { |h| h.credential = "key.secret" }
      ok = Class.new { def post_api(*, **) = FleetSimulator::Response.new(status: 200, body: '{"directives":{}}', headers: {}, ms: 1) }
      run = FleetSimulator::Runner.new(hosts:, transport: ok.new, payloads:, stats:, clock:, options: FleetSimulator::Options.parse(%w[--time-scale 60 --concurrency 2]))
      run.start(clock.now)
      rounds = 0
      run.run(clock.now + 3) { rounds += 1 }
      run.seed_snapshots(1)
      expect(rounds).to eq(60)
      expect(stats.summary(:inventory)[:count] + stats.summary(:heartbeat)[:count]).to be_positive
      expect(stats.status_counts(:seed)).to eq(200 => 3)
    end
  end

  describe FleetSimulator::FleetListProbe do
    it "times the fleet list as a signed-in operator and checks every simulated host is on it" do
      hosts = enrolled(2)
      cookie = FleetSimulator::OperatorCookie.header(HostSeparation.dashboard_host)
      probe = FleetSimulator::FleetListProbe.new(transport:, stats:, cookie:, host_names: hosts.map(&:name), interval: 10, clock:)
      probe.tick(clock.now)
      probe.tick(clock.now + 5) # not due yet
      expect(stats.of(:fleet_list).map { |s| [ s.status, s.note ] }).to eq([ [ 200, "/ listed 2/2" ], [ 200, "/?sort=status listed 2/2" ] ])

      missing = FleetSimulator::FleetListProbe.new(transport:, stats:, cookie:, host_names: %w[sim-001 sim-999], interval: 10, clock:)
      missing.probe("/", clock.now)
      expect(stats.of(:fleet_list).last).to have_attributes(status: "incomplete", note: "/ listed 1/2")
      FleetSimulator::FleetListProbe.new(transport:, stats:, cookie: "none=1", host_names: %w[sim-001], interval: 10, clock:).probe("/", clock.now)
      expect(stats.of(:fleet_list).last).to have_attributes(status: "incomplete", note: "/ listed 0/1")
    end

    it "never signs in to a production dashboard" do
      allow(Rails.env).to receive(:production?).and_return(true)
      expect { FleetSimulator::OperatorCookie.operator }.to raise_error(/never signs in to a production dashboard/)
    end
  end

  describe FleetSimulator::LivenessCheck do
    it "follows a silent host through stale and offline by the evaluation job, and back online by its heartbeat" do
      hosts = enrolled(1)
      run = runner(hosts, "--time-scale", "6") # heartbeat every 10 s
      # The server's clock follows the simulator's, so last_seen_at and the transitions line up with it.
      advance = ->(seconds) { clock.advance(seconds).tap { travel_to(clock.now, with_usec: true) } }
      check = FleetSimulator::LivenessCheck.new(host: hosts.first)
      check.prepare!
      expect(Setting.liveness_thresholds).to eq(online: 1.minute, stale: 2.minutes)
      run.start(clock.now)
      advance.(11)
      2.times { run.step(clock.now) }

      check.silence!(clock.now)
      expect(check.poll(clock.now)).to eq(:awaiting_stale)
      advance.(70)
      Liveness.evaluate!(now: clock.now)
      expect(check.poll(clock.now)).to eq(:awaiting_offline)
      advance.(60)
      Liveness.evaluate!(now: clock.now)
      expect(check.poll(clock.now)).to eq(:awaiting_online)
      expect(hosts.first.silent?(clock.now)).to be(false)
      run.step(clock.now)
      expect(check.poll(clock.now)).to eq(:passed)
      expect(check).to be_finished
      expect(check.log.join("\n")).to include("stopped heartbeating", "stale recorded", "offline recorded", "online recorded", "back online")

      check.restore!
      expect(Setting.liveness_thresholds).to eq(online: 3.minutes, stale: 15.minutes)
    end

    it "asks the database on every poll, even with the query cache on (as under bin/rails runner)" do
      # The liveness job writes from another process, which never clears this process's query cache, so a
      # cached answer would keep saying "no transition yet" (seen in a real run before this was fixed).
      check = FleetSimulator::LivenessCheck.new(host: enrolled(1).first)
      check.silence!(clock.now)
      cached = []
      watch = ->(*, payload) { cached << payload[:cached] if payload[:sql].include?("host_status_events") }
      ActiveSupport::Notifications.subscribed(watch, "sql.active_record") do
        ActiveRecord::Base.cache { 3.times { check.poll(clock.now) } }
      end
      expect(cached).to eq([ nil, nil, nil ])
    end

    it "fails when no transition is recorded in time, and restores nothing it did not change" do
      check = FleetSimulator::LivenessCheck.new(host: enrolled(1).first)
      check.restore!
      check.silence!(clock.now)
      clock.advance(200)
      expect(check.poll(clock.now)).to eq(:failed)
      expect(check.log.last).to include("no stale transition", "LivenessEvaluationJob")
      expect(check.poll(clock.now)).to eq(:failed)
    end
  end
end
