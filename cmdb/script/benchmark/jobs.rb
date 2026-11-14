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
      measurements.each do |name, (units, work, setup)|
        next if @only && !name.include?(@only)

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
      ApplicationRecord.connection.execute("UPDATE hosts SET liveness_status = 'online', last_seen_at = now() - random() * interval '50 seconds' " \
                                           "WHERE enrollment_state = 'active'")
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
        "CIS evaluation, every rule (per host)" => [ cis_hosts.size, -> { CisEvaluation.evaluate!(cis_hosts) } ],
        "vulnerability matching, every package (per host)" => [ package_hosts.size, -> { VulnerabilityMatcher.match!(package_hosts) } ],
        "advisory import: one changed source (per affected host)" => [ targeted, -> { VulnerabilityMatchJob.new.perform(packages: sources) } ],
        "retention prune, all tables (rolled back; per row deleted)" => [ retention_rows, -> { rolled_back { Retention.prune! } } ],
        "retention dry run (counts only)" => [ 1, -> { Retention.prune!(dry_run: true) } ],
        "task expiry and leases (per run)" => [ 1, -> { rolled_back { TaskLeases.expire! && TaskLeases.lapse! } } ]
      }
    end

    def retention_rows = @retention_rows ||= Retention.prune!(dry_run: true).values.sum
  end
end
