module FleetBenchmark
  # bin/benchmark explain: runs each probe (a hot path of the application, called through its real code) inside a
  # transaction that is rolled back, captures every statement it sends, and prints EXPLAIN (ANALYZE, BUFFERS) figures
  # for each: execution time, shared buffers hit and read, rows, and the sequential scans of large tables, which are the
  # statements that grow with the fleet. Writes are explained too, inside the same rolled-back transaction.
  class Explain
    SEQ_SCAN_ROWS = 10_000 # a sequential scan reading more rows than this is flagged

    def initialize(only: nil, verbose: false)
      @only = only
      @verbose = verbose
      @conn = ApplicationRecord.connection
    end

    def call
      probes.each do |name, probe|
        next if @only && !name.include?(@only)

        statements = capture(&probe)
        total = statements.sum { |s| explain(s).fetch(:ms) }
        puts format("== %-58s %3d statements, %9.1f ms in the database", name, statements.size, total)
        statements.each { |sql| print_plan(sql) }
      end
    end

    private

    def sample_host = @sample_host ||= Host.where("name LIKE 'bench-%'").where.not(name: "bench-0000000").order(:id).first
    def package_host = @package_host ||= Host.where(id: VulnerabilityFinding.select(:host_id)).where.not(name: "bench-0000000").order(:id).first

    def probes
      {
        "liveness evaluation (every minute)" => -> { Liveness.evaluate! },
        "fleet list /hosts (one page view)" => lambda {
          list = FleetList.new
          hosts = list.hosts.to_a
          FleetList.counts
          FleetList.tags
          FleetCompliance.rows_for(hosts.select { |h| h.enrollment_state == "active" })
          FleetCompliance.totals
        },
        # The one sort without an index (ADR 0026, #192): the first page, and the page after it.
        "fleet list sorted by last seen (first and second page)" => lambda {
          first = FleetList.new(sort: "last_seen").hosts.to_a
          FleetList.new(sort: "last_seen", after: first.last.id.to_s).hosts.to_a
        },
        "compliance /compliance (one page view)" => lambda {
          c = FleetCompliance.new
          FleetCompliance.totals
          c.rows
          FleetCompliance.tags
        },
        # VT-FIXABLE (#256): hosts with an open finding that has a fix, and of a severity with one.
        "compliance /compliance?fix=available and &vuln=high (one page view each)" => lambda {
          FleetCompliance.totals
          FleetCompliance.new(fix: "available").rows
          FleetCompliance.new(fix: "available").total
          FleetCompliance.new(fix: "available", vuln: "high").rows
        },
        # The per-host recount the summary triggers run at commit (ADR 0026), with the fix counts (#256): the counts
        # function alone, then the refresh that writes them.
        "compliance summary recount of one package host (counts with the fix flag)" => lambda {
          ids = "ARRAY[#{package_host.id}]::bigint[]"
          ApplicationRecord.connection.select_all("SELECT * FROM host_compliance_counts(#{ids})")
          ApplicationRecord.connection.select_all("SELECT host_compliance_summaries_refresh(#{ids})")
        },
        "task list /tasks (one page view)" => lambda {
          list = TaskList.new
          list.state_counts
          list.page
          list.batch_sizes
        },
        "audit log /audit (one page view)" => -> { AuditLog::Records.for(AuditLog.new.page.entries) },
        "audit log, filtered to one host" => -> { AuditLog.new(host_id: sample_host.id.to_s).page },
        "retention prune (first batch of each table)" => lambda {
          Retention.targets.each do |target|
            Retention.send(:expired_scope, target, Time.current - Setting.retention_window).limit(Retention::DEFAULT_BATCH_SIZE).pluck(:id)
          end
        },
        "advisory import: chunks and hosts with a changed source" => lambda {
          sources = [ FleetSimulator::Phase2.source_name(1) ]
          PackageChunkEntry.where("COALESCE(source, name) IN (?)", sources).distinct.pluck(:package_chunk_id)
          HostPackageSet.where(package_set_id: PackageSet.holding_sources(sources)).pluck(:host_id)
        },
        "packages tab /hosts/:id/packages (one page)" => lambda {
          list = HostPackageList.new(package_host.id, page: "9")
          list.total
          list.packages
          list.open_findings
        },
        "vulnerabilities tab /hosts/:id/vulnerabilities (open findings for the chip, package groups, one page)" => lambda {
          findings = VulnerabilityFinding.with_details.where(host_id: package_host.id)
          findings.active.preload(:advisory).to_a
          VulnerabilityFinding.where(host_id: package_host.id).group(:state, :fixable).count # the state and fix chips (#256)
          groups = HostFindingGroups.new(findings.joins(:advisory).preload(:advisory).where(state: %w[open reopened]), per_page: 10)
          HostFindingGroups.new(findings.joins(:advisory).preload(:advisory).where(state: %w[open reopened]), after: groups.next, per_page: 10) if groups.next
        },
        "vulnerabilities tab ?fix=available and ?fix=none (package groups, one page each)" => lambda {
          open = VulnerabilityFinding.with_details.where(host_id: package_host.id).joins(:advisory).preload(:advisory).where(state: %w[open reopened])
          HostFindingGroups.new(open.where(fixable: true), per_page: 50)
          HostFindingGroups.new(open.where(fixable: false), per_page: 50)
        },
        "CIS evaluation of one host (after a config snapshot)" => -> { CisEvaluation.evaluate!([ sample_host.id ]) },
        "vulnerability matching of one host (after a package snapshot)" => -> { VulnerabilityMatcher.match!([ package_host.id ]) },
        "task expiry and lease jobs (every minute)" => -> { TaskLeases.expire! && TaskLeases.lapse! },
        "host page /hosts/:id" => lambda {
          host = sample_host
          host.inventory_snapshots.order(received_at: :desc, id: :desc).limit(26).to_a
          host.status_events.order(occurred_at: :desc, id: :desc).limit(20).to_a
          AuditEntry.for_target(host).order(occurred_at: :desc, id: :desc).limit(20).to_a
        }
      }
    end

    # The statements a block sends, with binds inlined, in a transaction that is rolled back.
    def capture
      statements = []
      callback = lambda do |_name, _start, _finish, _id, event|
        next if %w[SCHEMA TRANSACTION].include?(event[:name])

        sql = event[:sql]
        next if sql.match?(/\A\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|EXPLAIN|SET|SHOW)/i)

        statements << inline(sql, event[:type_casted_binds])
      end
      ApplicationRecord.transaction do
        ActiveSupport::Notifications.subscribed(callback, "sql.active_record") do
          ApplicationRecord.uncached { yield }
        end
        raise ActiveRecord::Rollback
      end
      statements.uniq
    end

    def inline(sql, binds)
      binds = binds.respond_to?(:call) ? binds.call : binds
      return sql if binds.blank?

      sql.gsub(/\$(\d+)/) { @conn.quote(binds[Regexp.last_match(1).to_i - 1]) }
    end

    def explain(sql)
      @plans ||= {}
      @plans[sql] ||= begin
        plan = nil
        ApplicationRecord.transaction do
          plan = JSON.parse(@conn.select_value("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) #{sql}")).first
          raise ActiveRecord::Rollback
        end
        root = plan.fetch("Plan")
        { ms: plan.fetch("Execution Time"), hit: root["Shared Hit Blocks"].to_i, read: root["Shared Read Blocks"].to_i, rows: root["Actual Rows"].to_i,
          node: root["Node Type"], seq: seq_scans(root) }
      rescue ActiveRecord::StatementInvalid => e
        { ms: 0.0, hit: 0, read: 0, rows: 0, node: "error: #{e.message.lines.first.strip.truncate(80)}", seq: [] }
      end
    end

    def seq_scans(node, found = [])
      if node["Node Type"] == "Seq Scan" && node["Actual Rows"].to_i * node["Actual Loops"].to_i + node["Rows Removed by Filter"].to_i > SEQ_SCAN_ROWS
        found << "#{node['Relation Name']} (#{node['Actual Rows'].to_i + node['Rows Removed by Filter'].to_i} rows read)"
      end
      Array(node["Plans"]).each { |child| seq_scans(child, found) }
      found
    end

    def print_plan(sql)
      p = explain(sql)
      flag = p[:seq].any? ? "  SEQ SCAN #{p[:seq].join(', ')}" : ""
      puts format("  %9.2f ms %8d hit %7d read %8d rows  %-14s %s%s", p[:ms], p[:hit], p[:read], p[:rows], p[:node].to_s.truncate(14), sql.squish.sub(%r{ /\*.*\*/\z}, "").truncate(@verbose ? 2000 : 110), flag)
    end
  end
end
