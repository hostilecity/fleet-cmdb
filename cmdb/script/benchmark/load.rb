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
      "inventory" => [ "/api/v1/reports/inventory", false ],
      "config" => [ "/api/v1/reports/config", false ],
      "packages" => [ "/api/v1/reports/packages", true ],
      "poll" => [ "/api/v1/tasks/poll", false ]
    }.freeze
    # Requests per agent per hour on the default intervals.
    MIX = { "heartbeat" => 60.0, "poll" => 120.0, "inventory" => 4.0, "config" => 1 / 6.0, "packages" => 1 / 6.0 }.freeze
    POOL = 97 # distinct bodies per kind (a prime, so a host meets the same report id again only after POOL x hosts requests)

    def initialize(url:, kind: "heartbeat", threads: 8, duration: 30, hosts: 20_000, first_host: 1001, agent_host: nil)
      @uri = URI(url)
      @kind = kind
      @threads = threads
      @duration = duration
      @hosts = hosts
      @first_host = first_host
      @agent_host = agent_host || Rails.configuration.x.fleet_hosts.agent
      @payloads = Payloads.new
    end

    def call
      bodies = KINDS.keys.select { |k| @kind == "mix" || k == @kind }.to_h { |k| [ k, build_bodies(k) ] }
      before = db_counters
      samples = run(bodies)
      after = db_counters
      print_results(samples, after.to_h { |key, value| [ key, value - before.fetch(key, 0) ] })
    end

    private

    def build_bodies(kind)
      Array.new(POOL) do
        payload = case kind
        when "heartbeat" then @payloads.heartbeat(0)
        when "inventory" then @payloads.inventory(0)
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
        path, gzip = KINDS.fetch(kind)
        body = bodies.fetch(kind)[n % POOL]
        request = Net::HTTP::Post.new(path, "Content-Type" => "application/json", "Host" => @agent_host,
                                            "Authorization" => "Bearer #{FleetBenchmark.credential(@first_host + (n % @hosts))}")
        request["Content-Encoding"] = "gzip" if gzip
        request.body = body
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
      hosts = conn.select_one("SELECT n_tup_upd, n_tup_hot_upd, n_dead_tup FROM pg_stat_user_tables WHERE relname = 'hosts'")
      db.transform_values(&:to_i).merge("hosts_updates" => hosts["n_tup_upd"].to_i, "hosts_hot_updates" => hosts["n_tup_hot_upd"].to_i,
                                        "hosts_dead_tuples" => hosts["n_dead_tup"].to_i)
    end

    def print_results(samples, db)
      puts format("load: %s, %d threads, %d s, %d hosts, against %s", @kind, @threads, @duration, @hosts, @uri)
      puts format("%-10s %8s %8s %8s %8s %8s %8s  %-22s %9s %9s", "kind", "requests", "req/s", "p50 ms", "p90 ms", "p99 ms", "max ms", "statuses", "bytes in", "bytes out")
      samples.group_by(&:first).sort_by { |kind, _| KINDS.keys.index(kind) }.each { |kind, rows| print_row(kind, rows) }
      print_row("all", samples) if @kind == "mix"
      puts "database during the run (deltas): " + db.map { |key, value| "#{key}=#{value}" }.join(" ")
      ok = [ samples.count { |s| s[1].between?(200, 299) }, 1 ].max
      puts format("per successful request: %.2f commits, %.2f rows updated, %.2f rows inserted, %.1f buffer hits; hosts HOT updates %.0f%%",
                  db["xact_commit"].fdiv(ok), db["tup_updated"].fdiv(ok), db["tup_inserted"].fdiv(ok), db["blks_hit"].fdiv(ok),
                  100 * db["hosts_hot_updates"].fdiv([ db["hosts_updates"], 1 ].max))
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
