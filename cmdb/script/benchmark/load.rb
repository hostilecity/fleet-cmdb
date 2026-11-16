require "net/http"
require "zlib"

module FleetBenchmark
  # bin/benchmark load: closed-loop HTTP load against a running server, as the seeded hosts. THREADS client threads
  # each keep one keep-alive connection and send requests back to back for DURATION seconds, each request as the next
  # seeded host in turn, so no credential comes near the per-credential rate limit. Prints throughput, latency
  # percentiles, status counts, and payload sizes per request kind, and what the database did meanwhile (commits,
  # rows written, HOT updates of hosts).
  #
  # Kinds: heartbeat, inventory, config, packages, poll, or mix (the default intervals' proportions: a heartbeat a
  # minute, a task poll every 30 s, an inventory report every 15 min, a config and a package report every 6 h).
  class Load
    KINDS = {
      "heartbeat" => [ "/api/v1/heartbeat", false ],
      "inventory" => [ "/api/v1/reports/inventory", false ], # built per request, for its host (see #worker)
      "config" => [ "/api/v1/reports/config", false ],
      "packages" => [ "/api/v1/reports/packages", true ],
      "poll" => [ "/api/v1/tasks/poll", false ]
    }.freeze
    # Requests per agent per hour on the default intervals.
    MIX = { "heartbeat" => 60.0, "poll" => 120.0, "inventory" => 4.0, "config" => 1 / 6.0, "packages" => 1 / 6.0 }.freeze
    POOL = 97 # distinct bodies per kind (a prime, so a host meets the same report id again only after POOL x hosts requests)
    # The tables a heartbeat writes (#192); one that does not exist in this schema is left out.
    TRACKED = %w[hosts host_liveness].freeze
    # A backend reports its table statistics when it goes idle, at most every 10 s (PGSTAT_IDLE_INTERVAL), so the
    # counters are read this long after the last request.
    STATS_SETTLE = 11

    def initialize(url:, kind: "heartbeat", threads: 8, duration: 30, hosts: 20_000, first_host: 1001, agent_host: nil, warm: false)
      @uri = URI(url)
      @kind = kind
      @threads = threads
      @duration = duration
      @hosts = hosts
      @first_host = first_host
      @agent_host = agent_host || Rails.configuration.x.fleet_hosts.agent
      @warm = warm
      @payloads = Payloads.new
    end

    def call
      check_hosts!
      bodies = KINDS.keys.select { |k| @kind == "mix" || k == @kind }.without("inventory").to_h { |k| [ k, build_bodies(k) ] }
      warm_inventories if @warm
      sleep STATS_SETTLE if @warm
      before = db_counters
      wal = WalWindow.open(ApplicationRecord.connection)
      samples = run(bodies)
      wal.stop
      sleep STATS_SETTLE
      after = db_counters
      wal = wal.finish
      print_results(samples, after.to_h { |key, value| [ key, value.is_a?(Hash) ? value.to_h { |k, v| [ k, v - before.dig(key, k).to_i ] } : value - before.fetch(key, 0) ] }, wal)
    end

    private

    # Every host the run sends as must be a seeded host with an active credential: a missing one would answer 401
    # quickly and inflate the throughput (review of #188).
    def check_hosts!
      first, last = [ @first_host, @first_host + @hosts - 1 ].map { |i| FleetBenchmark.credential(i).split(".").first }
      found = AgentCredential.active.where(key_id: first..last).count
      return if found == @hosts

      abort "load: only #{found} of the #{@hosts} hosts from #{@first_host} have an active seeded credential; " \
            "adjust --first-host and --load-hosts to the seed (bin/benchmark seed --hosts)"
    end

    # A seeded host's inventory is a copy of the template's, so its first own report writes a snapshot and records its
    # machine id. --warm sends that first report to every host before the run, untimed, so the run measures steady reports.
    def warm_inventories
      counter = Concurrent::AtomicFixnum.new(-1)
      Array.new(@threads) do
        Thread.new do
          http = connect
          while (n = counter.increment) < @hosts
            http.request(request_for("inventory", @first_host + n, JSON.generate(@payloads.inventory(@first_host + n))))
          end
        end
      end.each(&:join)
    end

    def request_for(kind, host, body)
      path, gzip = KINDS.fetch(kind)
      request = Net::HTTP::Post.new(path, "Content-Type" => "application/json", "Host" => @agent_host,
                                          "Authorization" => "Bearer #{FleetBenchmark.credential(host)}")
      request["Content-Encoding"] = "gzip" if gzip
      request.body = body
      request
    end

    def build_bodies(kind)
      Array.new(POOL) do
        payload = case kind
        when "heartbeat" then @payloads.heartbeat(0)
        when "config" then @payloads.config(0)
        when "packages" then @payloads.packages(0)
        else @payloads.task_poll
        end
        payload["report_id"] = SecureRandom.uuid if payload.key?("report_id")
        json = JSON.generate(payload)
        KINDS.fetch(kind).last ? Zlib.gzip(json) : json
      end
    end

    def pick_kind(rng)
      return @kind unless @kind == "mix"

      roll = rng.rand * MIX.values.sum
      MIX.each { |kind, weight| return kind if (roll -= weight) <= 0 }
      MIX.keys.last
    end

    def run(bodies)
      counter = Concurrent::AtomicFixnum.new(0)
      deadline = FleetBenchmark.clock + @duration
      Array.new(@threads) { |t| Thread.new { worker(t, counter, deadline, bodies) } }.flat_map(&:value)
    end

    def worker(index, counter, deadline, bodies)
      rng = Random.new(index)
      http = connect
      samples = []
      while FleetBenchmark.clock < deadline
        n = counter.increment
        kind = pick_kind(rng)
        host = @first_host + (n % @hosts)
        # An inventory report names its host (hostname, machine id), so it is built for the host it is sent as; the
        # other kinds carry nothing host-specific and come from the pool.
        body = kind == "inventory" ? JSON.generate(@payloads.inventory(host)) : bodies.fetch(kind)[n % POOL]
        request = request_for(kind, host, body)
        started = FleetBenchmark.clock
        begin
          response = http.request(request)
          samples << [ kind, response.code.to_i, (FleetBenchmark.clock - started) * 1000, body.bytesize, response.body.to_s.bytesize ]
        rescue IOError, SystemCallError, Timeout::Error, Net::HTTPBadResponse => e
          samples << [ kind, 0, (FleetBenchmark.clock - started) * 1000, body.bytesize, 0 ]
          warn "[load] #{e.class}: #{e.message}" if samples.size < 5
          http = connect
        end
      end
      samples
    end

    def connect
      Net::HTTP.new(@uri.host, @uri.port).tap do |http|
        http.use_ssl = @uri.scheme == "https"
        http.open_timeout = http.read_timeout = 30
        http.keep_alive_timeout = 60
        http.start
      end
    end

    # Cumulative counters of the benchmark database, read before and after the run.
    def db_counters = ApplicationRecord.uncached { read_counters(ApplicationRecord.connection) }

    def read_counters(conn)
      db = conn.select_one("SELECT xact_commit, xact_rollback, tup_inserted, tup_updated, tup_deleted, blks_read, blks_hit, deadlocks " \
                           "FROM pg_stat_database WHERE datname = current_database()")
      tables = conn.select_rows(<<~SQL).to_h { |name, *values| [ name, %w[updates hot_updates dead_tuples heap_bytes index_bytes].zip(values.map(&:to_i)).to_h ] }
        SELECT relname, n_tup_upd, n_tup_hot_upd, n_dead_tup, pg_relation_size(relid), pg_indexes_size(relid)
          FROM pg_stat_user_tables WHERE relname IN (#{TRACKED.map { |t| conn.quote(t) }.join(', ')})
      SQL
      db.transform_values(&:to_i).merge(tables)
    end

    def print_results(samples, db, wal)
      puts format("load: %s, %d threads, %d s, %d hosts, against %s%s", @kind, @threads, @duration, @hosts, @uri, @warm ? ", inventories warmed" : "")
      if !@warm && %w[inventory mix].include?(@kind)
        puts "note: without --warm, a host's first inventory report in this database writes a snapshot (seeded inventories are the template's)"
      end
      puts format("%-10s %8s %8s %8s %8s %8s %8s  %-22s %9s %9s", "kind", "requests", "req/s", "p50 ms", "p90 ms", "p99 ms", "max ms", "statuses", "bytes in", "bytes out")
      samples.group_by(&:first).sort_by { |kind, _| KINDS.keys.index(kind) }.each { |kind, rows| print_row(kind, rows) }
      print_row("all", samples) if @kind == "mix"
      tables, totals = db.partition { |_, value| value.is_a?(Hash) }.map(&:to_h)
      puts "database during the run (deltas): " + totals.map { |key, value| "#{key}=#{value}" }.join(" ")
      ok = [ samples.count { |s| s[1].between?(200, 299) }, 1 ].max
      puts format("per successful request: %.2f commits, %.2f rows updated, %.2f rows inserted, %.1f buffer hits",
                  totals["xact_commit"].fdiv(ok), totals["tup_updated"].fdiv(ok), totals["tup_inserted"].fdiv(ok), totals["blks_hit"].fdiv(ok))
      tables.each do |name, t|
        puts format("  %-14s %.2f updates a request, HOT %.1f%%, dead tuples %+d, heap %+.1f KB, indexes %+.1f KB",
                    name, t["updates"].fdiv(ok), 100 * t["hot_updates"].fdiv([ t["updates"], 1 ].max), t["dead_tuples"],
                    t["heap_bytes"] / 1024.0, t["index_bytes"] / 1024.0)
      end
      print_wal(wal, ok)
    end

    def print_wal(wal, ok)
      unless wal.key?("wal_bytes")
        return puts(format("WAL: %.0f bytes a request, cluster-wide (other databases included)", wal["wal_cluster_bytes"].fdiv(ok)))
      end

      puts format("WAL in this database: %.0f bytes a request (%.0f of them full-page images), %.1f records a request; cluster-wide %.0f",
                  wal["wal_bytes"].fdiv(ok), wal["wal_fpi_bytes"].fdiv(ok), wal["wal_records"].fdiv(ok), wal["wal_cluster_bytes"].fdiv(ok))
      puts "  by relation, bytes a request: " + wal["wal_by_relation"].map { |name, bytes| format("%s %.0f", name, bytes.fdiv(ok)) }.join(", ")
    end

    def print_row(kind, rows)
      ms = rows.map { |r| r[2] }
      statuses = rows.map { |r| r[1] }.tally.sort.map { |s, n| "#{s}:#{n}" }.join(" ")
      puts format("%-10s %8d %8.1f %8.1f %8.1f %8.1f %8.1f  %-22s %9d %9d", kind, rows.size, rows.size.fdiv(@duration), FleetBenchmark.median(ms),
                  FleetBenchmark.percentile(ms, 90), FleetBenchmark.percentile(ms, 99), ms.max.to_f, statuses,
                  FleetBenchmark.median(rows.map { |r| r[3] }), FleetBenchmark.median(rows.map { |r| r[4] }))
    end
  end
end
