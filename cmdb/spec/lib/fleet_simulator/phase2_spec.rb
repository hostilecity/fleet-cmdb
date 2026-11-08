require "rails_helper"

# The simulator's Phase 2 load (P2-S12): configuration and package reports through the real agent API, the starter
# CIS rules and simulated advisories they are evaluated against, and the Phase 2 pages the probe times.
RSpec.describe "fleet simulator, Phase 2 (P2-S12)" do
  let(:transport) { FleetSimulatorHelpers::RackTransport.new }
  let(:clock) { FleetSimulatorHelpers::FakeClock.new }
  let(:payloads) { FleetSimulator::Payloads.new(agent_version: "0.1.0") }
  let(:state_file) { Rails.root.join("tmp/fleet_simulator/spec-#{SecureRandom.hex(4)}.json") }
  let(:stats) { FleetSimulator::Stats.new }

  after { FileUtils.rm_f(state_file) }

  def enrolled(count, **counts)
    FleetSimulator::Enroller.new(transport:, payloads:, via: "token", clock:, out: StringIO.new, state_file:)
                            .enroll_all(FleetSimulator::SimHost.build_all(count, counts:, now: clock.now))
  end

  def runner(hosts, *argv, transport: self.transport, probe: nil)
    FleetSimulator::Runner.new(hosts:, transport:, payloads:, stats:, options: simulator_options("--phase2", *argv), clock:, probe:)
  end

  describe FleetSimulator::Phase2 do
    it "gives every host the same packages, and upgrades the next vulnerable sources at each generation" do
      first = described_class.packages(0)
      expect(first.size).to eq(800)
      expect(first.map { |p| p["source"] }.uniq.size).to eq(300)
      vulnerable = ->(list) { list.select { |p| p["version"] == "1.4-1" }.map { |p| p["source"] }.uniq.size }
      expect([ vulnerable.(first), vulnerable.(described_class.packages(2)), vulnerable.(described_class.packages(30)), vulnerable.(described_class.packages(40)) ])
        .to eq([ 150, 140, 0, 0 ])
      expect(described_class.advisory_records.map { |r| r.dig("affected", 0, "package", "name") }).to eq((0...150).map { |i| format("simsrc-%03d", i) })
    end

    it "imports the starter CIS rules once, and the simulated advisories, audited as the system" do
      expect(described_class.prepare!).to match(/\Aimported \d+ starter CIS rules; imported 150 simulated advisories\z/)
      expect(CisRule.count).to be_positive
      expect(Advisory.where("advisory_id LIKE 'SIM-%'").count).to eq(150)
      expect(described_class.prepare!).to eq("kept the existing #{CisRule.count} CIS rules; imported 150 simulated advisories")
      expect(AuditEntry.where(actor_type: "system").where("action LIKE 'advisory.%'").count).to eq(2)
    end
  end

  describe FleetSimulator::Runner do
    it "seeds changed configuration and package reports, then sends both at startup and every report interval" do
      FleetSimulator::Phase2.prepare!
      hosts = enrolled(2, churn: 1)
      run = runner(hosts, "--time-scale", "3600", "--report-seconds", "3600", "--heartbeat-seconds", "36000", "--inventory-seconds", "36000")
      run.seed_reports(2)
      expect(stats.of(:seed_reports).map(&:note).tally).to eq("config" => 4, "packages" => 4)
      expect(stats.status_counts(:seed_reports)).to eq(200 => 8)
      expect(hosts.map(&:package_generation)).to eq([ 2, 2 ])

      run.start(clock.now)
      clock.advance(10.1)
      3.times { run.step(clock.now) } # inventory, then the reports, then the heartbeat
      expect(stats.status_counts(:config)).to eq(200 => 2)
      expect(stats.status_counts(:packages)).to eq(200 => 2)
      expect(hosts.map(&:package_generation)).to eq([ 2, 3 ]) # the churning host changed again
      clock.advance(1.2)
      run.step(clock.now)
      expect(stats.of(:packages).size).to eq(4) # again after the report interval (one second here)

      FleetSimulator::Phase2.evaluate!(hosts.map(&:host_id))
      steady, churning = hosts.map(&:host_id)
      expect(ConfigSnapshot.where(host_id: steady).count).to eq(2) # the seeded changes; startup repeated the last one
      expect(PackageSnapshot.where(host_id: churning).count).to be > PackageSnapshot.where(host_id: steady).count
      expect(CisResult.where(host_id: steady).count).to be_positive
      open = VulnerabilityFinding.where(host_id: steady).where.not(state: "resolved").count
      expect(open).to eq(FleetSimulator::Phase2.packages(2).count { |p| p["version"] == "1.4-1" })
    end

    it "waits out a rate limit while seeding, as an agent would" do
      hosts = enrolled(1)
      limited = Class.new(SimpleDelegator) do
        def post_api(path, payload, **options)
          if path.start_with?("/api/v1/reports/") && !@limited
            @limited = true
            return FleetSimulator::Response.new(status: 429, body: "{}", headers: { "retry-after" => "20" }, ms: 1)
          end
          __getobj__.post_api(path, payload, **options)
        end
      end
      before = clock.now
      runner(hosts, transport: limited.new(transport)).seed_reports(1)
      expect(clock.now - before).to eq(20)
      expect(stats.status_counts(:seed_reports)).to eq(200 => 2)
    end
  end

  describe FleetSimulator::FleetListProbe do
    it "times the Phase 2 pages and marks one without its expected content incomplete" do
      pages = [ FleetSimulator::FleetListProbe::Page.new(kind: :compliance, path: "/compliance", expect: "Compliance"),
                FleetSimulator::FleetListProbe::Page.new(kind: :vulnerabilities, path: "/compliance", expect: "SIM-not-there") ]
      FleetSimulator::FleetListProbe.new(transport:, stats:, cookie: FleetSimulator::OperatorCookie.header(HostSeparation.dashboard_host),
                                         host_names: [], interval: 10, clock:, pages:).tick(clock.now)
      expect([ stats.of(:compliance).sole.status, stats.of(:compliance).sole.note ]).to eq([ 200, "/compliance" ])
      expect([ stats.of(:vulnerabilities).sole.status, stats.of(:vulnerabilities).sole.note ]).to eq([ "incomplete", %(/compliance without "SIM-not-there") ])
    end
  end

  describe FleetSimulator::Options do
    it "adds Phase 2 to the load check, and checks its options" do
      expect(FleetSimulator::Options.parse(%w[--load-check])).to have_attributes(phase2: true, seed_reports: 13, report_interval: 5_400.0)
      expect(FleetSimulator::Options.parse(%w[--phase2 --report-seconds 60 --time-scale 2])).to have_attributes(phase2: true, report_interval: 30.0)
      expect { FleetSimulator::Options.parse(%w[--seed-reports 2]) }.to raise_error(OptionParser::InvalidArgument, /--seed-reports needs --phase2/)
      expect { FleetSimulator::Options.parse(%w[--phase2 --seed-reports -1]) }.to raise_error(OptionParser::InvalidArgument, /cannot be negative/)
      expect { FleetSimulator::Options.parse(%w[--report-seconds 0]) }.to raise_error(OptionParser::InvalidArgument, /--report-seconds must be positive/)
    end
  end

  describe FleetSimulator::CLI do
    let(:dir) { Rails.root.join("tmp/fleet_simulator/spec-#{SecureRandom.hex(4)}") }

    after { FileUtils.rm_rf(dir) }

    it "prepares the data, seeds and evaluates the hosts, and times the Phase 2 pages" do
      out = StringIO.new
      status = FleetSimulator::CLI.run(%W[--hosts 2 --duration 1m --phase2 --seed-reports 2 --probe-interval 20m --concurrency 1 --output #{dir}],
                                       out:, clock:, transport:, state_file: dir.join("credentials.json"))
      expect(status).to eq(0)
      expect(out.string).to include("Phase 2 data: imported", "Seeding 2 configuration and package reports per host",
                                    "Evaluating CIS rules and matching advisories for 2 hosts")
      summary = JSON.parse(dir.join("summary.json").read)
      expect(%w[compliance vulnerabilities package_diff].map { |kind| summary.dig("requests", kind, "statuses") }).to eq([ { "200" => 1 } ] * 3)
      expect(summary.dig("phase2", "open_findings")).to be_positive
    end
  end
end
