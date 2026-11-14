module FleetBenchmark
  # bin/benchmark queries: each agent request in process, through the real stack, with every SQL statement counted.
  # For each case, SAMPLES seeded hosts send the request (after one warm-up request each where the case is a steady
  # state), and the median and 99th percentile of the wall time, the SQL time, the statement count, and the rows
  # touched are printed; --verbose lists the statements of one request, so a new query shows up in review.
  class Queries
    Case = Data.define(:name, :warm, :request, :hosts) do
      def initialize(name:, warm:, request:, hosts: :idle) = super
    end

    def initialize(samples: 50, verbose: false, only: nil)
      @samples = samples
      @verbose = verbose
      @only = only
      @api = Api.new
      @payloads = Payloads.new
    end

    def call
      raise "no benchmark hosts: run bin/benchmark seed first" if sample_hosts(:idle).empty?

      puts format("%-30s %7s %8s %8s %8s %8s %6s %7s %9s %9s", "request", "status", "ms p50", "ms p99", "sql p50", "sql p99", "stmts", "rows", "bytes in", "bytes out")
      cases.each do |c|
        next if @only && !c.name.include?(@only)

        hosts = sample_hosts(c.hosts)
        next puts(format("%-30s skipped: no seeded host fits (for example no queued task left)", c.name)) if hosts.empty?

        print_case(c, run_case(c, hosts))
      end
    end

    private

    # :idle hosts have no open task; :queued hosts have one queued (the seed queues one on the first hosts).
    def sample_hosts(kind)
      open = Task.where(state: %w[queued claimed running]).select(:host_id)
      scope = Host.where("name LIKE 'bench-%'").where.not(name: "bench-0000000").where(enrollment_state: "active")
      scope = kind == :queued ? scope.where(id: Task.where(state: "queued").select(:host_id)) : scope.where.not(id: open)
      scope.order(:id).limit(@samples).pluck(:name).map { |name| name.delete_prefix("bench-").to_i }
    end

    def cases
      p = @payloads
      [
        Case.new("heartbeat (steady)", true, ->(i) { [ "/api/v1/heartbeat", p.heartbeat(i) ] }),
        Case.new("inventory (unchanged)", true, ->(i) { [ "/api/v1/reports/inventory", p.inventory(i) ] }),
        Case.new("inventory (kernel changed)", true, ->(i) { [ "/api/v1/reports/inventory", p.inventory(i, kernel: rand(1 << 30)) ] }),
        Case.new("config (unchanged)", true, ->(i) { [ "/api/v1/reports/config", p.config(i) ] }),
        Case.new("config (a fact changed)", true, ->(i) { [ "/api/v1/reports/config", p.config(i, generation: @step) ] }),
        Case.new("packages (unchanged, gzip)", true, ->(i) { [ "/api/v1/reports/packages", p.packages(i), true ] }),
        Case.new("packages (5 upgraded, gzip)", true, ->(i) { [ "/api/v1/reports/packages", p.packages(i, generation: @step), true ] }),
        Case.new("task poll (none queued)", false, ->(i) { [ "/api/v1/tasks/poll", p.task_poll ] }, :idle),
        Case.new("task poll (claims a task)", false, ->(i) { [ "/api/v1/tasks/poll", p.task_poll ] }, :queued)
      ]
    end

    # A host's seeded state is generation 0; the warm-up request is generation 1 and the measured one generation 2, so
    # a "changed" case changes something on every host.
    def run_case(c, hosts)
      hosts.map do |index|
        credential = FleetBenchmark.credential(index)
        (@step = 1) && send_request(c, index, credential) if c.warm
        @step = 2
        send_request(c, index, credential)
      end
    end

    def send_request(c, index, credential)
      path, body, gzip = c.request.(index)
      @api.post(path, body, credential:, gzip: gzip || false)
    end

    def print_case(c, results)
      ms = results.map(&:ms)
      sql = results.map(&:sql_ms)
      statuses = results.map(&:status).tally.map { |s, n| n == results.size ? s.to_s : "#{s}x#{n}" }.join(",")
      puts format("%-30s %7s %8.1f %8.1f %8.1f %8.1f %6d %7d %9d %9d", c.name, statuses, FleetBenchmark.median(ms), FleetBenchmark.percentile(ms, 99),
                  FleetBenchmark.median(sql), FleetBenchmark.percentile(sql, 99), FleetBenchmark.median(results.map(&:queries)),
                  FleetBenchmark.median(results.map(&:rows)), FleetBenchmark.median(results.map(&:bytes_in)), FleetBenchmark.median(results.map(&:bytes_out)))
      return unless @verbose

      results.last.statements.each { |statement| puts "    #{statement.squish.truncate(240)}" }
    end
  end
end
