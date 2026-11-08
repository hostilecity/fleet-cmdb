module FleetSimulator
  # The results of a run: a Markdown summary for the delivery note, the same as JSON, and every sample as CSV.
  # With --load-check or --liveness-check, the checks decide the exit status.
  class Report
    FLEET_LIST_TARGET_MS = 2_000 # NFR-3
    # The Phase 2 pages timed with --phase2, held to the fleet list's target (P2-S12).
    PHASE2_PAGES = { compliance: "Fleet compliance view", vulnerabilities: "Host vulnerabilities", package_diff: "Package comparison" }.freeze
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
        phase2: phase2_counts,
        requests: %i[heartbeat inventory duplicate seed config packages seed_reports fleet_list compliance vulnerabilities package_diff]
          .to_h { |kind| [ kind, @stats.summary(kind).merge(statuses: @stats.status_counts(kind)) ] },
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
                "Snapshots for these hosts: #{data[:snapshots]}. Status events: #{data[:status_events]}." +
                  (data[:phase2] ? " Phase 2: #{data[:phase2].map { |name, count| "#{name.to_s.tr('_', ' ')} #{count}" }.join(', ')}." : ""), "",
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

    # What the Phase 2 data amounts to for these hosts, or nil without --phase2.
    def phase2_counts
      return nil unless @options.phase2

      ids = @hosts.map(&:host_id)
      findings = VulnerabilityFinding.where(host_id: ids)
      { config_snapshots: ConfigSnapshot.where(host_id: ids).count, package_snapshots: PackageSnapshot.where(host_id: ids).count,
        cis_results: CisResult.where(host_id: ids).count, cis_failures: CisResult.where(host_id: ids, result: "fail").count,
        open_findings: findings.where.not(state: "resolved").count, resolved_findings: findings.where(state: "resolved").count }
    end

    def load_checks
      fleet = @stats.summary(:fleet_list)
      heartbeat = @stats.summary(:heartbeat)
      last_quarter = @stats.quarters(:heartbeat)[:last]
      simulated = (@finished_at - @started_at) * @options.time_scale
      [
        Check.new("At least #{Options::LOAD_CHECK[:hosts]} hosts reporting", reporting >= Options::LOAD_CHECK[:hosts],
                  "#{reporting} of #{@hosts.size} hosts had a heartbeat and an inventory report accepted in the run"),
        Check.new("At least one simulated hour", simulated >= SIMULATED_HOUR, "#{simulated.round} s simulated"),
        Check.new("Fleet list complete and under #{FLEET_LIST_TARGET_MS} ms every time", fleet[:count].positive? && fleet[:errors].zero? && fleet[:max].to_f < FLEET_LIST_TARGET_MS,
                  "#{fleet[:count]} loads, max #{fleet[:max]} ms, p95 #{fleet[:p95]} ms, #{fleet[:errors]} failed or incomplete"),
        Check.new("Heartbeat p95 under #{HEARTBEAT_P95_TARGET_MS} ms", heartbeat[:count].positive? && heartbeat[:p95].to_f < HEARTBEAT_P95_TARGET_MS,
                  "p95 #{heartbeat[:p95]} ms over #{heartbeat[:count]} heartbeats"),
        Check.new("Heartbeat p95 still under #{HEARTBEAT_P95_TARGET_MS} ms in the last quarter (no degradation)", last_quarter[:p95].to_f < HEARTBEAT_P95_TARGET_MS,
                  "first quarter #{@stats.quarters(:heartbeat)[:first][:p95]} ms, last quarter #{last_quarter[:p95]} ms"),
        *phase2_checks
      ]
    end

    def phase2_checks
      return [] unless @options.phase2

      accepted = ->(kind) { @stats.of(kind).select { |s| s.status.to_i.between?(200, 299) }.map(&:host).to_set }
      reported = (accepted.(:config) & accepted.(:packages)).size
      checks = [ Check.new("At least #{Options::LOAD_CHECK[:hosts]} hosts sent configuration and package reports", reported >= Options::LOAD_CHECK[:hosts],
                           "#{reported} of #{@hosts.size} hosts had both accepted in the run") ]
      PHASE2_PAGES.each do |kind, name|
        page = @stats.summary(kind)
        next if page[:count].zero? && kind == :package_diff

        checks << Check.new("#{name} complete and under #{FLEET_LIST_TARGET_MS} ms every time", page[:count].positive? && page[:errors].zero? && page[:max].to_f < FLEET_LIST_TARGET_MS,
                            "#{page[:count]} loads, max #{page[:max]} ms, p95 #{page[:p95]} ms, #{page[:errors]} failed or incomplete")
      end
      checks
    end

    # Hosts that took part in the measured run: at least one accepted heartbeat and one accepted report. Enrolled
    # hosts that sent nothing would otherwise pass for load (and pass the no-errors check by sending nothing).
    def reporting
      accepted = ->(kind) { @stats.of(kind).select { |s| s.status.to_i.between?(200, 299) }.map(&:host).to_set }
      (accepted.(:heartbeat) & accepted.(:inventory)).size
    end

    # Requests from well-behaved and misbehaving hosts alike must all be accepted, and duplicates recognised.
    def behaviour_checks
      failures = %i[heartbeat inventory seed config packages seed_reports].sum { |kind| @stats.summary(kind)[:errors] }
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
