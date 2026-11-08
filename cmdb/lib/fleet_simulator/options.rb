require "optparse"

module FleetSimulator
  # Command-line options for bin/simulate-fleet. Durations accept 90, 90s, 15m, or 2h.
  class Options
    # Simulated hosts take their addresses from the three documentation ranges (one /24 each).
    MAX_HOSTS = 750

    # The NFR-3 load check: 50 hosts for one simulated hour (15 minutes at four times the default rates), after
    # each host has accumulated 90 snapshots (one stable-field change a day for the default 90-day retention).
    # With Phase 2 (P2-S12): each host also sends its configuration and package reports at startup, after 13 seeded
    # changes (one a week for the 90-day retention), against the starter CIS rules and the simulated advisories.
    LOAD_CHECK = { hosts: 50, duration: 900, time_scale: 4.0, seed_snapshots: 90, phase2: true, seed_reports: 13 }.freeze

    DEFAULTS = {
      url: "http://127.0.0.1:3000", hosts: 10, duration: 600, time_scale: 1.0, enroll_via: "token",
      stop: 0, hostile: 0, churn: 0, duplicates: 0, seed_snapshots: 0, probe_interval: 10,
      heartbeat_seconds: 60, inventory_seconds: 900, agent_version: "0.1.0", concurrency: 16,
      load_check: false, liveness_check: false, output: nil, phase2: false, report_seconds: 21_600, seed_reports: 0
    }.freeze

    attr_reader(*DEFAULTS.keys)

    # Explicit options win over the --load-check presets, so a longer check is --load-check --duration 1h.
    def self.parse(argv)
      explicit = {}
      build_parser(explicit).parse!(argv.dup)
      values = DEFAULTS.dup
      values.merge!(LOAD_CHECK) if explicit[:load_check]
      new(**values.merge(explicit))
    end

    def self.build_parser(explicit)
      OptionParser.new do |o|
        o.banner = "Usage: bin/simulate-fleet [options]   (development server: FLEET_ENROLL_RATE_LIMIT_PER_MINUTE=100 bin/dev)"
        o.on("--url URL", "Server address to connect to (default #{DEFAULTS[:url]})") { |v| explicit[:url] = v }
        o.on("--hosts N", Integer, "Simulated hosts (default #{DEFAULTS[:hosts]}, at most #{MAX_HOSTS})") { |v| explicit[:hosts] = v }
        o.on("--duration TIME", "How long to run, in real time (default 10m)") { |v| explicit[:duration] = duration(v) }
        o.on("--time-scale X", Float, "Run X times faster than the configured intervals (default 1)") { |v| explicit[:time_scale] = v }
        o.on("--heartbeat-seconds N", Integer, "Heartbeat interval before scaling (default 60, FR-1.2)") { |v| explicit[:heartbeat_seconds] = v }
        o.on("--inventory-seconds N", Integer, "Inventory interval before scaling (default 900, FR-1.3)") { |v| explicit[:inventory_seconds] = v }
        o.on("--enroll-via WAY", %w[token onboarding], "token (pre-registration) or onboarding (auto-approved)") { |v| explicit[:enroll_via] = v }
        o.on("--stop N", Integer, "N hosts stop heartbeating and reporting halfway through") { |v| explicit[:stop] = v }
        o.on("--hostile N", Integer, "N hosts report markup and control-like Unicode in free-text fields") { |v| explicit[:hostile] = v }
        o.on("--churn N", Integer, "N hosts change a stable field in every inventory report") { |v| explicit[:churn] = v }
        o.on("--duplicates N", Integer, "N hosts resend every inventory report with the same report id") { |v| explicit[:duplicates] = v }
        o.on("--seed-snapshots N", Integer, "Before the run, give every host N snapshots through the API") { |v| explicit[:seed_snapshots] = v }
        o.on("--phase2", "Also send configuration and package reports, with the starter CIS rules and simulated advisories (P2-S12)") { explicit[:phase2] = true }
        o.on("--report-seconds N", Integer, "Configuration and package report interval before scaling (default 21600, P2-A01)") { |v| explicit[:report_seconds] = v }
        o.on("--seed-reports N", Integer, "With --phase2, before the run, every host sends N changed configuration and package reports") { |v| explicit[:seed_reports] = v }
        o.on("--probe-interval TIME", "How often to time the dashboard pages (default 10s)") { |v| explicit[:probe_interval] = duration(v) }
        o.on("--agent-version V", "Agent version the hosts report (default #{DEFAULTS[:agent_version]})") { |v| explicit[:agent_version] = v }
        o.on("--concurrency N", Integer, "Requests in flight at once (default #{DEFAULTS[:concurrency]})") { |v| explicit[:concurrency] = v }
        o.on("--load-check", "NFR-3: #{LOAD_CHECK[:hosts]} hosts, one simulated hour, checked against the targets") { explicit[:load_check] = true }
        o.on("--liveness-check", "AC-1.2, scaled down: one host goes silent and must turn stale, offline, then online") { explicit[:liveness_check] = true }
        o.on("--output DIR", "Where to write the results (default tmp/fleet_simulator/<time>)") { |v| explicit[:output] = v }
      end
    end

    # "90", "90s", "15m", "2h" -> seconds.
    def self.duration(text)
      match = text.to_s.strip.match(/\A(\d+(?:\.\d+)?)([smh]?)\z/) or raise OptionParser::InvalidArgument, text
      match[1].to_f * { "" => 1, "s" => 1, "m" => 60, "h" => 3600 }.fetch(match[2])
    end

    def self.help = build_parser({}).help

    def initialize(**values)
      DEFAULTS.each_key { |key| instance_variable_set(:"@#{key}", values.fetch(key)) }
      validate!
    end

    # Real seconds between a host's heartbeats and between its inventory reports.
    def heartbeat_interval = heartbeat_seconds / time_scale
    def inventory_interval = inventory_seconds / time_scale
    def report_interval = report_seconds / time_scale

    # Simulated time the run covers.
    def simulated_seconds = duration * time_scale

    private

    def validate!
      raise OptionParser::InvalidArgument, "--hosts must be between 1 and #{MAX_HOSTS}" unless hosts.between?(1, MAX_HOSTS)
      raise OptionParser::InvalidArgument, "--time-scale must be positive" unless time_scale.positive?
      raise OptionParser::InvalidArgument, "--duration and --probe-interval must be positive" unless duration.positive? && probe_interval.positive?
      raise OptionParser::InvalidArgument, "--concurrency must be at least 1" unless concurrency >= 1
      raise OptionParser::InvalidArgument, "--heartbeat-seconds, --inventory-seconds, and --report-seconds must be positive" unless [ heartbeat_seconds, inventory_seconds, report_seconds ].all?(&:positive?)
      raise OptionParser::InvalidArgument, "--seed-reports needs --phase2" if seed_reports.positive? && !phase2
      raise OptionParser::InvalidArgument, "--liveness-check needs a --duration of at least 10m" if liveness_check && duration < 600
      behaviours = [ stop, hostile, churn, duplicates ]
      raise OptionParser::InvalidArgument, "behaviour counts cannot be negative" if behaviours.any?(&:negative?) || seed_snapshots.negative? || seed_reports.negative?
      raise OptionParser::InvalidArgument, "--stop, --hostile, --churn, and --duplicates together exceed --hosts" if behaviours.sum > hosts
    end
  end
end
