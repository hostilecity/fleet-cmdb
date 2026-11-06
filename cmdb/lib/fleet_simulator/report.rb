module FleetSimulator
  # The results of a run: a Markdown summary for the delivery note, the same as JSON, and every sample as CSV.
  # With --load-check or --liveness-check, the checks decide the exit status.
  class Report
    FLEET_LIST_TARGET_MS = 2_000 # NFR-3
    HEARTBEAT_P95_TARGET_MS = 200 # NFR-3
    SIMULATED_HOUR = 3_600

    Check = Data.define(:name, :passed, :detail)

    def initialize(options:, stats:, hosts:, started_at:, finished_at:, liveness: nil)
      @options = options
      @stats = stats
      @hosts = hosts
      @started_at = started_at
      @finished_at = finished_at
      @liveness = liveness
    end

    def checks
      list = []
      list.concat(load_checks) if @options.load_check
      list.concat(behaviour_checks)
      list << Check.new("Stopped host turned stale, then offline, then online (AC-1.2)", @liveness.state == :passed, @liveness.log.last) if @liveness
      list
    end

    def passed? = checks.all?(&:passed)

    def summary
      {
        started_at: @started_at.utc.iso8601, finished_at: @finished_at.utc.iso8601,
        hosts: @hosts.size, enrolled: @hosts.count(&:credential), behaviours: @hosts.filter_map(&:behaviour).tally,
        real_seconds: (@finished_at - @started_at).round, simulated_seconds: ((@finished_at - @started_at) * @options.time_scale).round,
        time_scale: @options.time_scale,
        snapshots: InventorySnapshot.where(host_id: @hosts.map(&:host_id)).count,
        status_events: HostStatusEvent.where(host_id: @hosts.map(&:host_id)).count,
        requests: %i[heartbeat inventory duplicate seed fleet_list].to_h { |kind| [ kind, @stats.summary(kind).merge(statuses: @stats.status_counts(kind)) ] },
        heartbeat_quarters: @stats.quarters(:heartbeat),
        liveness: @liveness&.log,
        checks: checks.map(&:to_h)
      }
    end

    def markdown
      data = summary
      lines = [ "# Fleet simulator results", "",
                "#{data[:hosts]} hosts (#{data[:enrolled]} enrolled), #{data[:real_seconds]} s real time at #{@options.time_scale}x " \
                "= #{data[:simulated_seconds]} s simulated, #{data[:started_at]} to #{data[:finished_at]}.",
                "Behaviours: #{data[:behaviours].presence&.map { |b, n| "#{b} #{n}" }&.join(', ') || 'none'}. " \
                "Snapshots for these hosts: #{data[:snapshots]}. Status events: #{data[:status_events]}.", "",
                "| Requests | Count | Errors | p50 ms | p95 ms | p99 ms | Max ms | Statuses |", "|---|---|---|---|---|---|---|---|" ]
      data[:requests].each do |kind, s|
        next if s[:count].zero?

        lines << "| #{kind} | #{s[:count]} | #{s[:errors]} | #{s[:p50]} | #{s[:p95]} | #{s[:p99]} | #{s[:max]} | #{s[:statuses].map { |k, v| "#{k}: #{v}" }.join(', ')} |"
      end
      quarters = data[:heartbeat_quarters]
      lines += [ "", "Heartbeat p95: first quarter #{quarters[:first][:p95]} ms, last quarter #{quarters[:last][:p95]} ms." ]
      lines += [ "", "## Liveness check", "" ] + data[:liveness].map { |line| "- #{line}" } if data[:liveness]
      lines += [ "", "## Checks", "" ] + checks.map { |c| "- [#{c.passed ? 'x' : ' '}] #{c.name}: #{c.detail}" } if checks.any?
      lines.join("\n") << "\n"
    end

    # Writes summary.md, summary.json and samples.csv to dir. Returns dir.
    def write(dir)
      dir = Pathname(dir)
      dir.mkpath
      dir.join("summary.md").write(markdown)
      dir.join("summary.json").write(JSON.pretty_generate(summary))
      dir.join("samples.csv").write(@stats.to_csv)
      dir
    end

    private

    def load_checks
      fleet = @stats.summary(:fleet_list)
      heartbeat = @stats.summary(:heartbeat)
      last_quarter = @stats.quarters(:heartbeat)[:last]
      simulated = (@finished_at - @started_at) * @options.time_scale
      [
        Check.new("At least #{Options::LOAD_CHECK[:hosts]} hosts enrolled and reporting", @hosts.count(&:credential) >= Options::LOAD_CHECK[:hosts], "#{@hosts.count(&:credential)} hosts"),
        Check.new("At least one simulated hour", simulated >= SIMULATED_HOUR, "#{simulated.round} s simulated"),
        Check.new("Fleet list complete and under #{FLEET_LIST_TARGET_MS} ms every time", fleet[:count].positive? && fleet[:errors].zero? && fleet[:max].to_f < FLEET_LIST_TARGET_MS,
                  "#{fleet[:count]} loads, max #{fleet[:max]} ms, p95 #{fleet[:p95]} ms, #{fleet[:errors]} failed or incomplete"),
        Check.new("Heartbeat p95 under #{HEARTBEAT_P95_TARGET_MS} ms", heartbeat[:count].positive? && heartbeat[:p95].to_f < HEARTBEAT_P95_TARGET_MS,
                  "p95 #{heartbeat[:p95]} ms over #{heartbeat[:count]} heartbeats"),
        Check.new("Heartbeat p95 still under #{HEARTBEAT_P95_TARGET_MS} ms in the last quarter (no degradation)", last_quarter[:p95].to_f < HEARTBEAT_P95_TARGET_MS,
                  "first quarter #{@stats.quarters(:heartbeat)[:first][:p95]} ms, last quarter #{last_quarter[:p95]} ms")
      ]
    end

    # Requests from well-behaved and misbehaving hosts alike must all be accepted, and duplicates recognised.
    def behaviour_checks
      failures = %i[heartbeat inventory seed].sum { |kind| @stats.summary(kind)[:errors] }
      list = [ Check.new("Every heartbeat and report accepted", failures.zero?, "#{failures} failed") ]
      duplicates = @stats.of(:duplicate)
      if duplicates.any?
        missed = duplicates.count { |s| s.note != "duplicate" }
        list << Check.new("Every resent report answered duplicate: true (AC-1.4)", missed.zero?, "#{duplicates.size} resent, #{missed} not recognised")
      end
      list
    end
  end
end
