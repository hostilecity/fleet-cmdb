module FleetSimulator
  # bin/simulate-fleet: enrolls the hosts, optionally seeds their history, runs the fleet for the duration while
  # timing the fleet list and running the liveness check, and writes the results. Returns the exit status: 0, 1 when
  # a check failed, 2 for a usage error.
  class CLI
    LIVENESS_START_AFTER = 30 # seconds, so the fleet has settled first
    POLL_EVERY = 5
    PROGRESS_EVERY = 60

    def self.run(argv, **dependencies) = new(**dependencies).run(argv)

    def initialize(out: $stdout, clock: Clock.new, transport: nil, state_file: Enroller::DEFAULT_STATE_FILE)
      @out = out
      @clock = clock
      @transport = transport
      @state_file = state_file
    end

    def run(argv)
      return usage(Options.help, 0) if argv.intersect?(%w[-h --help])

      options = Options.parse(argv)
      raise "bin/simulate-fleet is for development and test servers only" if Rails.env.production?

      simulate(options)
    rescue OptionParser::ParseError => e
      usage("#{e.message}\n\n#{Options.help}", 2)
    end

    private

    def usage(text, status)
      @out.puts text
      status
    end

    def simulate(options)
      transport = @transport || HttpTransport.new(url: options.url, agent_host: HostSeparation.agent_host,
                                                  dashboard_host: HostSeparation.dashboard_host, clock: @clock)
      payloads = Payloads.new(agent_version: options.agent_version)
      hosts = SimHost.build_all(options.hosts, now: @clock.now,
                                counts: { stop: options.stop, hostile: options.hostile, churn: options.churn, duplicates: options.duplicates })
      @out.puts "Enrolling #{hosts.size} hosts through #{options.url} (#{options.enroll_via})..."
      Enroller.new(transport:, payloads:, via: options.enroll_via, clock: @clock, out: @out, state_file: @state_file).enroll_all(hosts)

      stats = Stats.new
      probe = FleetListProbe.new(transport:, stats:, cookie: OperatorCookie.header(HostSeparation.dashboard_host),
                                 host_names: hosts.map(&:name), interval: options.probe_interval, clock: @clock)
      runner = Runner.new(hosts:, transport:, payloads:, stats:, options:, clock: @clock, probe:)
      if options.seed_snapshots.positive?
        @out.puts "Seeding #{options.seed_snapshots} snapshots per host..."
        runner.seed_snapshots(options.seed_snapshots)
      end

      liveness = options.liveness_check ? LivenessCheck.new(host: hosts.find { |h| h.behaviour.nil? } || hosts.first) : nil
      started_at, finished_at = run_fleet(options, runner, stats, liveness)
      finish(options, stats, hosts, started_at, finished_at, liveness)
    end

    def run_fleet(options, runner, stats, liveness)
      liveness&.prepare!
      started_at = @clock.now
      runner.start(started_at)
      @out.puts "Running #{runner.hosts.size} hosts for #{options.duration.round} s at #{options.time_scale}x " \
                "(heartbeat every #{options.heartbeat_interval.round(1)} s, inventory every #{options.inventory_interval.round(1)} s)..."
      next_poll = started_at
      next_progress = started_at + PROGRESS_EVERY
      runner.run(started_at + options.duration) do |now|
        next_poll = poll_liveness(liveness, started_at, now) if liveness && now >= next_poll
        next_progress = progress(stats, now) if now >= next_progress
      end
      [ started_at, @clock.now ]
    ensure
      liveness&.restore!
    end

    def poll_liveness(liveness, started_at, now)
      if liveness.state == :idle
        liveness.silence!(now) if now >= started_at + LIVENESS_START_AFTER
      elsif !liveness.finished?
        before = liveness.log.size
        liveness.poll(now)
        liveness.log.drop(before).each { |line| @out.puts "  liveness: #{line}" }
      end
      now + POLL_EVERY
    end

    def progress(stats, now)
      heartbeat = stats.summary(:heartbeat)
      fleet = stats.summary(:fleet_list)
      @out.puts "  #{now.utc.iso8601}: #{heartbeat[:count]} heartbeats (p95 #{heartbeat[:p95]} ms, #{heartbeat[:errors]} failed), " \
                "fleet list max #{fleet[:max]} ms"
      now + PROGRESS_EVERY
    end

    def finish(options, stats, hosts, started_at, finished_at, liveness)
      report = Report.new(options:, stats:, hosts:, started_at:, finished_at:, liveness:)
      dir = report.write(options.output || Rails.root.join("tmp/fleet_simulator", started_at.utc.strftime("%Y%m%dT%H%M%SZ")))
      @out.puts report.markdown, "Results written to #{dir}"
      report.passed? ? 0 : 1
    end
  end
end
