module FleetBenchmark
  # bin/benchmark jobs: times the background work whose cost grows with the fleet, through the real code, and prints
  # the median and spread of REPEAT runs with the per-host (or per-row) cost, so a fleet-wide figure can be
  # extrapolated. Work that writes is rolled back where the measurement allows it (liveness, retention, task jobs); CIS
  # evaluation and vulnerability matching are idempotent on seeded data, so they run for real. A measurement's setup (a
  # healthy fleet for liveness) runs in the same rolled-back transaction, outside the timing.
  class Jobs
    def initialize(repeat: 3, samples: 200, only: nil)
      @repeat = repeat
      @samples = samples
      @only = only
    end

    def call
      puts format("%-58s %10s %10s %10s %8s %12s", "job", "median ms", "min ms", "max ms", "units", "ms per unit")
      measurements.each do |name, (units, work, setup, warm)|
        next if @only && !name.include?(@only)

        work.call if warm # the first run may write what later runs do not (the seed's resolved findings reopen), so it is not timed

        times = Array.new(@repeat) { setup ? rolled_back { setup.call && time(&work) } : time(&work) }
        median = FleetBenchmark.median(times)
        puts format("%-58s %10.1f %10.1f %10.1f %8d %12.3f", name, median, times.min, times.max, units, median / [ units, 1 ].max)
      end
    end

    private

    def time
      started = FleetBenchmark.clock
      yield
      (FleetBenchmark.clock - started) * 1000
    end

    def rolled_back
      result = nil
      ApplicationRecord.transaction do
        result = yield
        raise ActiveRecord::Rollback
      end
      result
    end

    # Every active host heartbeated within the last 50 seconds and is online, as in a healthy fleet.
    def fresh_heartbeats
      ApplicationRecord.connection.execute("UPDATE host_liveness SET liveness_status = 'online', last_seen_at = now() - random() * interval '50 seconds'")
    end

    def bench_hosts = Host.where("name LIKE 'bench-%'").where.not(name: "bench-0000000")

    def measurements
      active = Host.active.count
      cis_hosts = bench_hosts.order(:id).limit(@samples).pluck(:id)
      package_hosts = bench_hosts.where(id: HostPackage.select(:host_id)).order(:id).limit(@samples).pluck(:id)
      sources = { "Debian:13" => [ FleetSimulator::Phase2.source_name(1) ] }
      targeted = HostPackage.where("COALESCE(source, name) IN (?)", sources.values.flatten).distinct.count(:host_id)
      {
        # Both start from a healthy fleet (rolled back afterwards). Steady: nothing changes. Mass: evaluated 20 minutes later,
        # so every host goes offline at once, as after a server outage.
        "liveness evaluation, steady (per active host)" => [ active, -> { Liveness.evaluate! }, -> { fresh_heartbeats } ],
        "liveness evaluation, all go offline (per host)" => [ active, -> { Liveness.evaluate!(now: Time.current + 20.minutes) }, -> { fresh_heartbeats } ],
        "CIS evaluation, every rule (per host)" => [ cis_hosts.size, -> { CisEvaluation.evaluate!(cis_hosts) }, nil, true ],
        "vulnerability matching, every package (per host)" => [ package_hosts.size, -> { VulnerabilityMatcher.match!(package_hosts) }, nil, true ],
        "advisory import: one changed source (per affected host)" => [ targeted, -> { EvaluationRun::Advisories.new("packages" => sources).call(Host.minimum(:id)..Host.maximum(:id)) }, nil, true ],
        # Row deletes: the tables that are not partitioned, and the legacy partition of a converted table (ADR 0027).
        "retention prune, row deletes (rolled back; per row deleted)" => [ retention_rows, -> { rolled_back { Retention.prune! } } ],
        # Partitions past the window detached and dropped, each host's newest row moved forward first (ADR 0027).
        "retention retire partitions (rolled back; per partition)" => [ retired["partitions"], -> { rolled_back { Retention.retire! } } ],
        "retention dry run (counts only)" => [ 1, -> { Retention.prune!(dry_run: true) && Retention.retire!(dry_run: true) } ],
        "task expiry and leases (per run)" => [ 1, -> { rolled_back { TaskLeases.expire! && TaskLeases.lapse! } } ]
      }
    end

    def retention_rows = @retention_rows ||= Retention.prune!(dry_run: true).values.sum

    # What one retirement run would do, summed over the tables: partitions, rows in them, and rows moved forward.
    def retired
      @retired ||= Retention.retire!(dry_run: true).values.each_with_object(Hash.new(0)) { |r, sum| r.each { |k, v| sum[k] += v } }.tap do |r|
        puts "retirement due: #{r['partitions']} partitions, #{r['rows']} rows dropped, #{r['moved']} kept rows moved forward"
      end
    end
  end
end
