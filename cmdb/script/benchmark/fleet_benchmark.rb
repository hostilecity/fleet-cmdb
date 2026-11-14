# bin/benchmark: a scale benchmark for the agent API, the database, the jobs, and the dashboard. Development and test
# databases only. See docs/operations/benchmark.md for the procedure and how to read the results.
#
#   bin/benchmark seed --hosts 100000       # a scale dataset (script/benchmark/seed.rb)
#   bin/benchmark queries                   # queries, rows, and time per agent request, in process
#   bin/benchmark explain                   # EXPLAIN (ANALYZE, BUFFERS) of every statement of the hot paths
#   bin/benchmark jobs                      # per-host cost of the fleet-wide jobs
#   bin/benchmark load --url URL            # HTTP load against a running server, with the seeded credentials
#
# It reuses the fleet simulator's Phase 2 data (lib/fleet_simulator/phase2.rb), so the template host has the same
# packages, rules, and advisories as the NFR-3 load check.
require "json"
require "securerandom"
require Rails.root.join("lib/fleet_simulator").to_s

module FleetBenchmark
  TAG = "benchmark".freeze
  AGENT_VERSION = "0.3.0".freeze

  module_function

  def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  # The credential of seeded host i (0 is the template). Benchmark data only: never use this scheme for real hosts.
  def credential(index) = format("fb_%010d.benchmark-secret-%010d-0123456789abcdef", index, index)

  # The same, as SQL for an integer expression.
  def credential_sql(index_sql)
    "'fb_' || lpad((#{index_sql})::text, 10, '0') || '.benchmark-secret-' || lpad((#{index_sql})::text, 10, '0') || '-0123456789abcdef'"
  end

  def median(values) = percentile(values, 50)

  def percentile(values, pct)
    return 0.0 if values.empty?

    sorted = values.sort
    sorted[((pct / 100.0) * (sorted.size - 1)).round]
  end

  # Request bodies from the shared contract examples (docs/api/examples), as the simulator builds them.
  class Payloads
    def example(name, file) = FleetSimulator::Payloads.example(name, file)

    def heartbeat(index)
      example("heartbeat.request", "tasks").merge("agent_version" => AGENT_VERSION, "hostname" => hostname(index), "agent_time" => Time.now.utc.iso8601(3))
    end

    def inventory(index, kernel: 0)
      example("inventory.request", "full").merge(
        "agent_version" => AGENT_VERSION, "report_id" => SecureRandom.uuid, "collected_at" => Time.now.utc.iso8601, "hostname" => hostname(index),
        "machine_id" => machine_id(index), "kernel_version" => "6.12.0-bench.#{kernel}-amd64", "memory_available_bytes" => 4_000_000_000 + rand(1 << 26)
      )
    end

    def config(index, generation: 0)
      report = example("config.request", "typical").merge("agent_version" => AGENT_VERSION, "report_id" => SecureRandom.uuid, "collected_at" => Time.now.utc.iso8601)
      report["facts"]["sshd.permitrootlogin"] = { "state" => "ok", "value" => generation.odd? ? "yes" : "no", "reason" => nil }
      report
    end

    def packages(_index, generation: 0)
      example("packages.request", "dpkg").merge("agent_version" => AGENT_VERSION, "report_id" => SecureRandom.uuid, "collected_at" => Time.now.utc.iso8601,
                                               "packages" => FleetSimulator::Phase2.packages(generation))
    end

    def task_poll = { "schema_version" => 1, "agent_version" => AGENT_VERSION, "agent_state" => "idle" }

    def hostname(index) = format("bench-%07d.example.lan", index)
    def machine_id(index) = Digest::SHA256.hexdigest("fleet-benchmark #{index}")[0, 32]
  end

  # The agent API in process, through the whole Rails stack (middleware, routing, controllers), so a request's
  # queries can be counted exactly. Not a substitute for the HTTP load test: no server, no network, one thread.
  class Api
    Result = Data.define(:status, :body, :ms, :queries, :rows, :sql_ms, :bytes_in, :bytes_out, :statements)

    def initialize
      @session = ActionDispatch::Integration::Session.new(Rails.application)
      @session.host = Rails.configuration.x.fleet_hosts.agent
      @session.https!
    end

    def post(path, payload, credential:, gzip: false)
      body = JSON.generate(payload)
      headers = { "Content-Type" => "application/json", "Authorization" => "Bearer #{credential}" }
      if gzip
        body = ActiveSupport::Gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
      end
      # In its own thread: a request run in process resets the caller's execution context (the runner's) when it ends.
      measure { Thread.new { @session.post(path, params: body, headers:) }.value }.then { |status, ms, sql| result(status, ms, sql, body.bytesize) }
    end

    def post!(path, payload, credential:)
      result = post(path, payload, credential:)
      raise "#{path} answered #{result.status}: #{result.body.truncate(300)}" unless result.status.between?(200, 299)

      result
    end

    private

    def measure
      sql = []
      callback = lambda do |_name, started, finished, _id, event|
        next if %w[SCHEMA TRANSACTION].include?(event[:name]) || event[:sql].match?(/\A\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)/i)

        sql << [ event[:sql], (finished - started) * 1000, event[:row_count].to_i ]
      end
      started = FleetBenchmark.clock
      status = ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
      [ status, (FleetBenchmark.clock - started) * 1000, sql ]
    end

    def result(status, ms, sql, bytes_in)
      Result.new(status:, body: @session.response.body, ms:, queries: sql.size, rows: sql.sum(&:last), sql_ms: sql.sum { |s| s[1] },
                 bytes_in:, bytes_out: @session.response.body.bytesize, statements: sql.map(&:first))
    end
  end
end

require_relative "seed"
require_relative "queries"
require_relative "explain"
require_relative "jobs"
require_relative "load"
require_relative "cli"
