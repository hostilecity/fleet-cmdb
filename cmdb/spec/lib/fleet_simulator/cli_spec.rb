require "rails_helper"

RSpec.describe FleetSimulator::CLI do
  let(:out) { StringIO.new }
  let(:clock) { FleetSimulatorHelpers::FakeClock.new }
  let(:transport) { FleetSimulatorHelpers::RackTransport.new }
  let(:dir) { Rails.root.join("tmp/fleet_simulator/spec-#{SecureRandom.hex(4)}") }
  let(:state_file) { dir.join("credentials.json") }

  after { FileUtils.rm_rf(dir) }

  def run(*argv) = described_class.run(argv, out:, clock:, transport:, state_file:)

  it "prints its options" do
    expect(run("--help")).to eq(0)
    expect(out.string).to include("Usage: bin/simulate-fleet", "--load-check")
  end

  it "explains a usage error" do
    expect(run("--hosts", "0")).to eq(2)
    expect(out.string).to include("--hosts must be between 1 and 750", "Usage:")
  end

  it "refuses a production server" do
    allow(Rails.env).to receive(:production?).and_return(true)
    expect { run }.to raise_error(/development and test servers only/)
  end

  it "silences the liveness host only after its heartbeat has been accepted in this run" do
    host = FleetSimulator::SimHost.new(index: 1)
    check = FleetSimulator::LivenessCheck.new(host:)
    cli = described_class.new(out:, clock:, transport:, state_file:)
    started = clock.now
    cli.send(:poll_liveness, check, started, started + 45)
    expect(check.state).to eq(:idle) # 30 s are up, but the host has not been heard from
    host.last_heartbeat_at = started + 40
    cli.send(:poll_liveness, check, started, started + 50)
    expect(check.state).to eq(:awaiting_stale)
  end

  it "enrolls, seeds, runs, times the fleet list, runs the liveness check, and writes the results" do
    # Few requests per host, for the test environment's rate limit of 10 a minute per credential. Nothing runs
    # the liveness job here, so the liveness check runs out of time and the exit status is 1.
    status = run("--hosts", "2", "--duration", "10m", "--time-scale", "0.5", "--seed-snapshots", "1", "--probe-interval", "20m",
                 "--concurrency", "1", "--liveness-check", "--output", dir.to_s)
    expect(status).to eq(1)
    expect(out.string).to include("Enrolling 2 hosts", "Seeding 1 snapshots per host", "Running 2 hosts for 600 s at 0.5x",
                                  "liveness: ", "stopped heartbeating", "no stale transition", "heartbeats (p95", "Results written to #{dir}")
    expect(dir.children.map { |f| f.basename.to_s }).to contain_exactly("credentials.json", "summary.md", "summary.json", "samples.csv")
    summary = JSON.parse(dir.join("summary.json").read)
    expect(summary.dig("requests", "fleet_list", "count")).to eq(2)
    expect(summary.dig("requests", "seed", "statuses")).to eq("200" => 2)
    expect(summary["checks"].map { |c| [ c["name"].first(25), c["passed"] ] }).to eq([ [ "Every heartbeat and repor", true ], [ "Stopped host turned stale", false ] ])
    expect(Setting.liveness_thresholds).to eq(online: 3.minutes, stale: 15.minutes) # restored
  end
end

RSpec.describe FleetSimulator::Report do
  let(:stats) { FleetSimulator::Stats.new }
  let(:start) { Time.utc(2026, 1, 1, 12) }
  let(:hosts) { FleetSimulator::SimHost.build_all(50, counts: { duplicates: 1 }).each { |h| h.credential = "key.secret" } }

  def report(finish: start + 900, liveness: nil)
    described_class.new(options: FleetSimulator::Options.parse(%w[--load-check]), stats:, hosts:, started_at: start, finished_at: finish, liveness:)
  end

  def record(kind, ms, status: 200, note: nil, at: start, host: "sim-001")
    stats.record(kind:, host:, status:, ms:, at:, note:)
  end

  # Every host sends one accepted inventory, configuration, and package report, so the fleet counts as reporting.
  def whole_fleet_reports = hosts.each { |h| %i[inventory config packages].each { |kind| record(kind, 30, host: h.name) } }

  it "passes a load check that meets the NFR-3 targets" do
    whole_fleet_reports
    100.times { |i| record(:heartbeat, 20 + i % 10, at: start + i, host: hosts[i % 50].name) }
    record(:fleet_list, 350)
    %i[compliance vulnerabilities package_diff].each { |kind| record(kind, 400) }
    record(:duplicate, 10, note: "duplicate")
    expect(report.checks.map(&:passed)).to all(be(true))
    expect(report).to be_passed
    expect(report.markdown).to include("50 hosts (50 enrolled), 900 s real time at 4.0x = 3600 s simulated", "Behaviours: duplicates 1",
                                       "| heartbeat | 100 | 0 | 24", "- [x] Fleet list complete and under 2000 ms every time",
                                       "Phase 2: config snapshots 0, package snapshots 0, cis results 0, cis failures 0, open findings 0, resolved findings 0.",
                                       "- [x] At least 50 hosts sent configuration and package reports: 50 of 50",
                                       "- [x] Fleet compliance view complete and under 2000 ms every time", "- [x] Host vulnerabilities complete",
                                       "- [x] Package comparison complete", "| packages | 50 | 0 |")
  end

  it "fails on a slow or incomplete fleet list, a slow heartbeat p95 or last quarter, too short a run, refusals, and missed duplicates" do
    80.times { |i| record(:heartbeat, 50, at: start + i) } # all from one host: the fleet did not report
    20.times { |i| record(:heartbeat, 250, at: start + 100 + i) }
    record(:fleet_list, 2_400)
    record(:fleet_list, 100, status: "incomplete")
    record(:inventory, 12, status: 422, note: "rejected")
    record(:duplicate, 10, note: "not recognised as a duplicate")
    record(:compliance, 2_500)
    record(:vulnerabilities, 100, status: "incomplete")
    failed = report(finish: start + 600).checks.reject(&:passed).map(&:name)
    expect(failed).to contain_exactly("At least 50 hosts reporting", "At least one simulated hour", "Fleet list complete and under 2000 ms every time", "Heartbeat p95 under 200 ms",
                                      "Heartbeat p95 still under 200 ms in the last quarter (no degradation)", "Every heartbeat and report accepted",
                                      "Every resent report answered duplicate: true (AC-1.4)", "At least 50 hosts sent configuration and package reports",
                                      "Fleet compliance view complete and under 2000 ms every time", "Host vulnerabilities complete and under 2000 ms every time")
    expect(report.checks.map(&:name)).not_to include(a_string_starting_with("Package comparison")) # not timed: no seeded reports
    expect(report.markdown).to include("- [ ] Heartbeat p95 under 200 ms: p95 250 ms over 100 heartbeats")
  end

  it "includes the liveness check and its log" do
    liveness = FleetSimulator::LivenessCheck.new(host: hosts.first)
    liveness.instance_variable_set(:@state, :passed)
    liveness.log << "back online"
    text = report(liveness:).markdown
    expect(text).to include("## Liveness check", "- back online", "- [x] Stopped host turned stale, then offline, then online (AC-1.2): back online")
  end
end
