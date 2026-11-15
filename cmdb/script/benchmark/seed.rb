# Seeds a scale dataset for bin/benchmark (see docs/operations/benchmark.md). Development and test databases only.
#
# One template host is created through the real code paths: a heartbeat, an inventory report, a config report, and a
# package report through FleetBenchmark::Api (in process, the real controllers), then CIS evaluation and vulnerability
# matching. Its rows are then copied in SQL (generate_series) to HOSTS hosts, with the history a host accumulates
# over the retention window. So the data has the shapes and sizes the application writes, at a scale the API could
# not reach in a reasonable time.
#
# Every seeded host is named bench-NNNNNNN and tagged "benchmark"; its credential is FleetBenchmark.credential(i).
module FleetBenchmark
  class Seed
    DEFAULTS = {
      hosts: 100_000,
      package_hosts: 10_000,  # hosts that also get the template's package rows, findings, and package snapshots
      inventory_snapshots: 6, # per host, spread over the retention window (a stable-field change every two weeks)
      config_snapshots: 3,
      package_snapshots: 4,   # per package host
      status_events: 12,
      receipts: 12,           # per host and report type; an agent sends 96 inventory receipts a day
      audit_entries: 4,       # per host, besides those the template's tasks write
      task_hosts: 10_000,     # hosts that get finished tasks
      tasks_per_host: 2,
      queued_tasks: 1_000     # hosts with one queued task each, among the first hosts
    }.freeze

    def initialize(**options)
      @o = DEFAULTS.merge(options.compact)
      @conn = ApplicationRecord.connection
    end

    def call
      refuse_production!
      log "seeding #{@o.inspect}"
      phase("template") { template }
      phase("hosts and credentials") { hosts }
      phase("current state") { current_state }
      phase("packages") { packages }
      phase("history") { history }
      phase("tasks and audit") { tasks_and_audit }
      phase("analyze") { run_sql("ANALYZE") }
      report_sizes
    end

    private

    def refuse_production!
      raise "bin/benchmark seed refuses to run in production" if Rails.env.production?
      # Some phases update rows in bulk; on an empty database they can only touch what the seed wrote (review of #188).
      raise "bin/benchmark seed needs an empty database: reset it first (bin/rails db:schema:load)" if Host.exists? || Task.exists?
    end

    def log(message) = puts("[seed] #{message}")

    # Each phase starts with no cached plans, and plans with parameters are always made for their values (#192). The
    # compliance summaries' triggers plan for what they see: a query over a trigger's transition tables has no
    # parameters, so PL/pgSQL keeps the first plan it made in the session, and one made for the template's one-row
    # updates (a nested loop) took over 20 minutes on the 100,000-row UPDATE of hosts. A query with an array of host
    # ids switches to a generic plan, made for an array of about 10, after five runs; the CIS results copy then ran
    # for over 30 minutes.
    def phase(name)
      run_sql("DISCARD PLANS")
      run_sql("SET plan_cache_mode = force_custom_plan")
      started = FleetBenchmark.clock
      yield
      log format("%-22s %8.1f s", name, FleetBenchmark.clock - started)
    end

    def run_sql(sql) = @conn.execute(sql)

    # The template host, through the real API and jobs.
    def template
      log FleetSimulator::Phase2.prepare!
      host = Host.create!(name: "bench-0000000", hostname: "bench-0000000.example.lan", tags: [ FleetBenchmark::TAG ])
      Host.where(id: host.id).update_all(enrollment_state: "active")
      plaintext = FleetBenchmark.credential(0)
      key_id, secret = plaintext.split(".")
      AgentCredential.create!(host:, key_id:, secret_digest: AgentApi.digest(secret))
      api = Api.new
      payloads = Payloads.new
      api.post!("/api/v1/heartbeat", payloads.heartbeat(0), credential: plaintext)
      api.post!("/api/v1/reports/inventory", payloads.inventory(0), credential: plaintext)
      api.post!("/api/v1/reports/config", payloads.config(0), credential: plaintext)
      api.post!("/api/v1/reports/packages", payloads.packages(0), credential: plaintext)
      FleetSimulator::Phase2.evaluate!([ host.id ])
      @template = host.id
      log "template host #{host.id}: #{HostPackage.where(host_id: host.id).count} packages, #{CisResult.where(host_id: host.id).count} CIS results, " \
          "#{VulnerabilityFinding.where(host_id: host.id).count} findings"
    end

    # Hosts bench-0000001.. as pending (the database's rule for new hosts), then active and online, each with a credential.
    def hosts
      n = @o[:hosts]
      run_sql(<<~SQL)
        INSERT INTO hosts (name, hostname, tags, enrollment_state, created_at, updated_at)
        SELECT 'bench-' || lpad(i::text, 7, '0'), 'bench-' || lpad(i::text, 7, '0') || '.example.lan',
               ARRAY['#{FleetBenchmark::TAG}', 'rack-' || (i % 50)]::varchar[], 'pending', now() - interval '120 days', now()
        FROM generate_series(1, #{n}) i
      SQL
      t = Host.find(@template)
      run_sql(<<~SQL)
        UPDATE hosts SET enrollment_state = 'active', liveness_status = 'online', first_seen_at = now() - interval '100 days',
               last_seen_at = now() - random() * interval '50 seconds', agent_version = #{q(t.agent_version)},
               agent_schema_version = #{t.agent_schema_version}, agent_reported_at = now(), task_catalog_version = #{t.task_catalog_version.to_i},
               task_types_supported = #{q_array(t.task_types_supported)}, task_types_enabled = #{q_array(t.task_types_enabled)},
               task_services_allowed = #{q_array(t.task_services_allowed)}, task_capabilities_reported_at = now()
        WHERE name LIKE 'bench-%' AND id <> #{@template}
      SQL
      run_sql(<<~SQL)
        INSERT INTO agent_credentials (host_id, key_id, secret_digest, state, created_at, updated_at)
        SELECT h.id, split_part(c.plaintext, '.', 1), encode(sha256(convert_to(split_part(c.plaintext, '.', 2), 'UTF8')), 'hex'), 'active', now(), now()
        FROM hosts h CROSS JOIN LATERAL (SELECT #{FleetBenchmark.credential_sql("substr(h.name, 7)::int")} AS plaintext) c
        WHERE h.name LIKE 'bench-%' AND h.id <> #{@template}
      SQL
    end

    # The template's current rows, once per host.
    def current_state
      copy("host_inventories", "host_id", "stable, volatile, warnings, stable_hash, gen_random_uuid(), schema_version, collected_at, received_at, created_at, updated_at",
           columns: "stable, volatile, warnings, stable_hash, report_id, schema_version, collected_at, received_at, created_at, updated_at")
      copy("host_configs", "host_id", "facts, content_hash, state_counts, manifest_version, ignored_keys, gen_random_uuid(), schema_version, collected_at, received_at, created_at, updated_at",
           columns: "facts, content_hash, state_counts, manifest_version, ignored_keys, report_id, schema_version, collected_at, received_at, created_at, updated_at")
      copy("host_package_sets", "host_id",
           "manager, unsupported_reason, package_count, content_hash, warnings, gen_random_uuid(), schema_version, collected_at, received_at, created_at, updated_at, skipped",
           columns: "manager, unsupported_reason, package_count, content_hash, warnings, report_id, schema_version, collected_at, received_at, created_at, updated_at, skipped")
      copy("cis_results", "host_id", "cis_rule_id, cis_rule_version_id, NULL, result, observed, reason, evaluated_at, changed_at",
           columns: "cis_rule_id, cis_rule_version_id, config_snapshot_id, result, observed, reason, evaluated_at, changed_at")
      copy("host_vulnerability_evaluations", "host_id", "ecosystem, state, reason, detail, not_evaluated, not_evaluated_count, evaluated_at, created_at, updated_at",
           columns: "ecosystem, state, reason, detail, not_evaluated, not_evaluated_count, evaluated_at, created_at, updated_at")
    end

    # Package rows and findings for the first package_hosts hosts.
    def packages
      limit = "AND substr(h.name, 7)::int <= #{@o[:package_hosts]}"
      copy("host_packages", "host_id", "name, architecture, version, source", columns: "name, architecture, version, source", where: limit)
      copy("vulnerability_findings", "host_id",
           "advisory_id, package, architecture, source, ecosystem, installed_version, fixed_version, state, resolution, first_seen_at, resolved_at, reopened_at, created_at, updated_at",
           columns: "advisory_id, package, architecture, source, ecosystem, installed_version, fixed_version, state, resolution, first_seen_at, resolved_at, reopened_at, created_at, updated_at",
           where: limit)
      # Some resolved findings too, as upgrades leave them: a fifth of the open ones, resolved 30 to 120 days ago.
      run_sql(<<~SQL)
        UPDATE vulnerability_findings SET state = 'resolved', resolution = 'fixed', resolved_at = now() - (30 + (id % 90)) * interval '1 day'
        WHERE id % 5 = 0 AND host_id IN (SELECT id FROM hosts WHERE name LIKE 'bench-%' AND id <> #{@template})
      SQL
    end

    def history
      window = Setting.retention_window.to_i
      bench = "h.name LIKE 'bench-%'"
      # Spread over 1.2 windows, so some rows are past the window and retention has work to do.
      spread = ->(count) { "now() - (s::float / #{count}) * #{(window * 1.2).to_i} * interval '1 second'" }
      # Materialised, for the reason given in #copy.
      template_row = ->(table) { "WITH t AS MATERIALIZED (SELECT * FROM #{table} WHERE host_id = #{@template} ORDER BY received_at DESC LIMIT 1)" }
      run_sql(<<~SQL)
        #{template_row.('inventory_snapshots')}
        INSERT INTO inventory_snapshots (host_id, stable, warnings, stable_hash, report_id, collected_at, received_at)
        SELECT h.id, t.stable, t.warnings, md5(h.id::text || s), gen_random_uuid(), #{spread.(@o[:inventory_snapshots])}, #{spread.(@o[:inventory_snapshots])}
        FROM hosts h CROSS JOIN t CROSS JOIN generate_series(1, #{@o[:inventory_snapshots]}) s WHERE #{bench}
      SQL
      # A third of the hosts are stable: their inventory has not changed within the window, so every one of their snapshots
      # is older than it and the newest is kept however old (Retention's keep_newest_per_host).
      run_sql(<<~SQL)
        UPDATE inventory_snapshots SET received_at = received_at - #{window} * interval '1 second', collected_at = collected_at - #{window} * interval '1 second'
        WHERE host_id % 3 = 0 AND host_id <> #{@template}
      SQL
      run_sql(<<~SQL)
        #{template_row.('config_snapshots')}
        INSERT INTO config_snapshots (host_id, facts, content_hash, state_counts, manifest_version, report_id, collected_at, received_at)
        SELECT h.id, t.facts, md5(h.id::text || s), t.state_counts, t.manifest_version, gen_random_uuid(), #{spread.(@o[:config_snapshots])}, #{spread.(@o[:config_snapshots])}
        FROM hosts h CROSS JOIN t CROSS JOIN generate_series(1, #{@o[:config_snapshots]}) s WHERE #{bench}
      SQL
      run_sql(<<~SQL)
        #{template_row.('package_snapshots')}
        INSERT INTO package_snapshots (host_id, manager, unsupported_reason, package_count, content_hash, packages, warnings, report_id, collected_at, received_at, skipped)
        SELECT h.id, t.manager, t.unsupported_reason, t.package_count, md5(h.id::text || s), t.packages, t.warnings, gen_random_uuid(),
               #{spread.(@o[:package_snapshots])}, #{spread.(@o[:package_snapshots])}, t.skipped
        FROM hosts h CROSS JOIN t CROSS JOIN generate_series(1, #{@o[:package_snapshots]}) s
        WHERE #{bench} AND substr(h.name, 7)::int BETWEEN 1 AND #{@o[:package_hosts]}
      SQL
      %w[inventory_report_receipts config_report_receipts package_report_receipts].each do |table|
        run_sql(<<~SQL)
          INSERT INTO #{table} (host_id, report_id, received_at)
          SELECT h.id, gen_random_uuid(), #{spread.(@o[:receipts])} FROM hosts h CROSS JOIN generate_series(1, #{@o[:receipts]}) s WHERE #{bench}
        SQL
      end
      run_sql(<<~SQL)
        INSERT INTO host_status_events (host_id, from_status, to_status, reason, occurred_at)
        SELECT h.id, CASE WHEN s % 2 = 0 THEN 'online' ELSE 'stale' END, CASE WHEN s % 2 = 0 THEN 'stale' ELSE 'online' END,
               CASE WHEN s % 2 = 0 THEN 'evaluation' ELSE 'heartbeat' END, #{spread.(@o[:status_events])}
        FROM hosts h CROSS JOIN generate_series(1, #{@o[:status_events]}) s WHERE #{bench}
      SQL
      rule = CisRule.order(:id).first
      run_sql(<<~SQL) if rule
        INSERT INTO cis_result_changes (host_id, cis_rule_id, cis_rule_version_id, from_result, to_result, reason, occurred_at)
        SELECT h.id, #{rule.id}, #{rule.current_version_id}, CASE WHEN s % 2 = 0 THEN 'pass' ELSE 'fail' END,
               CASE WHEN s % 2 = 0 THEN 'fail' ELSE 'pass' END, NULL, #{spread.(@o[:config_snapshots])}
        FROM hosts h CROSS JOIN generate_series(1, #{@o[:config_snapshots]}) s WHERE #{bench}
      SQL
    end

    # Finished tasks (queued, claimed, running, then succeeded, as the database requires), their audit trail, and the
    # entries enrollment and reports leave.
    def tasks_and_audit
      operator = Operator.find_or_create_by!(google_uid: "benchmark") { |o| o.email = "benchmark@example.com"; o.name = "Benchmark" }
      type = "refresh_reports"
      catalog = TaskCatalog.current
      batch_ids = run_sql(<<~SQL).values.flatten
        INSERT INTO task_batches (operator_id, task_type, parameters, selection_method, selected_host_ids, excluded_hosts, confirmed_host_count, catalog_version, catalog_digest, created_at)
        SELECT #{operator.id}, '#{type}', '{}', 'explicit', ARRAY[1]::bigint[], '[]', 25, #{catalog.version}, #{q(catalog.digest)}, now() - (b % 90) * interval '1 day'
        FROM generate_series(1, #{[ (@o[:task_hosts] * @o[:tasks_per_host] / 25.0).ceil, 1 ].max}) b RETURNING id
      SQL
      task_hosts = "SELECT id, row_number() OVER (ORDER BY id) AS n FROM hosts WHERE name LIKE 'bench-%' AND id <> #{@template} ORDER BY id LIMIT #{@o[:task_hosts]}"
      run_sql(<<~SQL)
        INSERT INTO tasks (task_batch_id, host_id, task_type, parameters, state, timeout_seconds, expires_at, created_at, updated_at)
        SELECT (ARRAY[#{batch_ids.join(',')}]::bigint[])[1 + ((h.n * #{@o[:tasks_per_host]} + s) / 25) % #{batch_ids.size}], h.id, '#{type}', '{}', 'queued', 600,
               now() - (s * 7) * interval '1 day' + interval '24 hours', now() - (s * 7) * interval '1 day', now()
        FROM (#{task_hosts}) h CROSS JOIN generate_series(1, #{@o[:tasks_per_host]}) s
      SQL
      seeded = "task_batch_id = ANY (ARRAY[#{batch_ids.join(',')}]::bigint[])"
      run_sql("UPDATE tasks SET state = 'claimed', claimed_at = created_at, lease_expires_at = created_at + interval '5 minutes' WHERE #{seeded}")
      run_sql("UPDATE tasks SET state = 'running', started_at = created_at, lease_expires_at = created_at + interval '15 minutes' WHERE #{seeded}")
      run_sql(<<~SQL)
        UPDATE tasks SET state = 'succeeded', finished_at = created_at + interval '1 minute', exit_status = 0, output = 'reports sent',
               result_report_id = gen_random_uuid(), result_digest = md5(id::text) || md5(id::text), result_received_at = created_at + interval '1 minute'
        WHERE #{seeded}
      SQL
      run_sql(<<~SQL)
        INSERT INTO tasks (task_batch_id, host_id, task_type, parameters, state, timeout_seconds, expires_at, created_at, updated_at)
        SELECT #{batch_ids.first}, h.id, '#{type}', '{}', 'queued', 600, now() + interval '24 hours', now(), now()
        FROM (#{task_hosts.sub("LIMIT #{@o[:task_hosts]}", "LIMIT #{@o[:queued_tasks]}")}) h
      SQL
      run_sql(<<~SQL)
        INSERT INTO audit_entries (actor_type, actor_id, action, target_type, target_id, changeset, occurred_at)
        SELECT CASE WHEN a.action = 'task.created' THEN 'operator' ELSE 'host' END, CASE WHEN a.action = 'task.created' THEN #{operator.id} ELSE t.host_id END,
               a.action, 'Task', t.id, jsonb_build_object('state', jsonb_build_array(NULL, a.action)), t.created_at
        FROM tasks t CROSS JOIN (VALUES ('task.created'), ('task.claimed'), ('task.started'), ('task.succeeded')) a(action)
        WHERE t.#{seeded}
      SQL
      run_sql(<<~SQL)
        INSERT INTO audit_entries (actor_type, actor_id, action, target_type, target_id, changeset, occurred_at)
        SELECT 'system', NULL, (ARRAY['host.enrolled', 'host.first_inventory', 'host.updated', 'host.report_requested'])[1 + s % 4], 'Host', h.id,
               '{}'::jsonb, now() - (s * 20) * interval '1 day'
        FROM hosts h CROSS JOIN generate_series(1, #{@o[:audit_entries]}) s WHERE h.name LIKE 'bench-%'
      SQL
    end

    # Copies the template's rows of table to every seeded host (subject to where), replacing host_id.
    def copy(table, host_column, select, columns:, where: "")
      # The template rows are materialised first: read from the table being filled, they would be scanned again for every
      # host, and each scan reads the pages written so far.
      run_sql(<<~SQL)
        WITH t AS MATERIALIZED (SELECT * FROM #{table} WHERE #{host_column} = #{@template})
        INSERT INTO #{table} (#{host_column}, #{columns})
        SELECT h.id, #{select.split(', ').map { |c| c.include?('(') || c == 'NULL' ? c : "t.#{c}" }.join(', ')}
        FROM hosts h CROSS JOIN t
        WHERE h.name LIKE 'bench-%' AND h.id <> #{@template} #{where}
      SQL
    end

    def report_sizes
      rows = run_sql(<<~SQL).to_a
        SELECT c.relname AS table, c.reltuples::bigint AS rows, pg_total_relation_size(c.oid) AS total_bytes, pg_relation_size(c.oid) AS heap_bytes,
               pg_indexes_size(c.oid) AS index_bytes
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 25
      SQL
      log "table sizes (bytes per row = total / rows):"
      rows.each do |r|
        per_row = r["rows"].to_i.positive? ? r["total_bytes"].to_i / r["rows"].to_i : 0
        log format("  %-34s %12d rows %10s total %10s heap %10s indexes %7d B/row", r["table"], r["rows"], human(r["total_bytes"]), human(r["heap_bytes"]),
                   human(r["index_bytes"]), per_row)
      end
      log "database: #{human(run_sql('SELECT pg_database_size(current_database())').first.values.first)}"
    end

    def human(bytes) = ActiveSupport::NumberHelper.number_to_human_size(bytes.to_i)
    def q(value) = @conn.quote(value)
    def q_array(values) = "ARRAY[#{values.map { |v| q(v) }.join(',')}]::varchar[]"
  end
end
