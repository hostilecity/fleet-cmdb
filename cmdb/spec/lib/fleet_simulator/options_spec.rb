require "rails_helper"

RSpec.describe FleetSimulator::Options do
  it "defaults to ten hosts on the agent's default intervals" do
    options = described_class.parse([])
    expect([ options.hosts, options.heartbeat_interval, options.inventory_interval, options.load_check ]).to eq([ 10, 60, 900, false ])
  end

  it "sets up the NFR-3 load check: 50 hosts for one simulated hour with accumulated snapshots" do
    options = described_class.parse(%w[--load-check])
    expect([ options.hosts, options.simulated_seconds, options.seed_snapshots, options.load_check ]).to eq([ 50, 3600, 90, true ])
    expect(options.heartbeat_interval).to eq(15)
  end

  it "lets explicit options override the load check presets" do
    expect(described_class.parse(%w[--load-check --duration 1h --time-scale 1]).simulated_seconds).to eq(3600)
  end

  it "parses every option" do
    options = described_class.parse(%w[--url http://192.0.2.1:3000 --hosts 20 --duration 90s --time-scale 2.5 --heartbeat-seconds 30
                                       --inventory-seconds 600 --enroll-via onboarding --stop 1 --hostile 2 --churn 3 --duplicates 4
                                       --seed-snapshots 5 --probe-interval 2m --agent-version 0.2.0 --concurrency 4 --liveness-check
                                       --duration 10m --output /tmp/out])
    expect(options).to have_attributes(url: "http://192.0.2.1:3000", hosts: 20, duration: 600, time_scale: 2.5, heartbeat_seconds: 30,
                                       inventory_seconds: 600, enroll_via: "onboarding", stop: 1, hostile: 2, churn: 3, duplicates: 4,
                                       seed_snapshots: 5, probe_interval: 120, agent_version: "0.2.0", concurrency: 4,
                                       liveness_check: true, output: "/tmp/out")
    expect(options.heartbeat_interval).to eq(12)
  end

  it "reads durations in seconds, minutes, and hours" do
    expect(%w[45 45s 3m 2h 1.5m].map { |text| described_class.duration(text) }).to eq([ 45, 45, 180, 7200, 90 ])
    expect { described_class.duration("soon") }.to raise_error(OptionParser::InvalidArgument)
  end

  it "rejects impossible combinations" do
    [ %w[--hosts 0], %w[--hosts 751], %w[--time-scale 0], %w[--duration 0], %w[--concurrency 0], %w[--stop -1],
      %w[--seed-snapshots -1], %w[--hosts 2 --stop 2 --churn 1], %w[--liveness-check --duration 5m], %w[--enroll-via email] ].each do |argv|
      expect { described_class.parse(argv) }.to raise_error(OptionParser::ParseError), argv.join(" ")
    end
  end

  it "describes itself" do
    expect(described_class.help).to include("--load-check", "--liveness-check", "FLEET_ENROLL_RATE_LIMIT_PER_MINUTE")
  end
end
