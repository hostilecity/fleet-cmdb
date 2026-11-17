# Time partitions of the history tables (ADR 0027, #195, P1-S10). Retention drops a whole partition instead of
# deleting its rows one by one, so its daily cost no longer grows with the rows written.
#
# - TABLES names each partitioned table, its partition key, and its width: report receipts by day, snapshots, status
#   events, and CIS result changes by week (30 days when the retention window is over 180 days; a changed width
#   applies to partitions created after the change), and the audit log by calendar month.
# - Partitions are named <table>_pYYYYMMDD after their first day, and form one contiguous chain. A table converted from
#   the old schema also has <table>_legacy, holding every row from before the conversion (MINVALUE up to the
#   cutover); it ages out like any partition (Retention).
# - ensure! creates partitions AHEAD of now (3 days, 3 weeks, or 3 months), and a default partition for every table
#   except the audit log, so a write never fails because a partition is missing. The audit log has no default: it
#   fails closed (FR-S.3), and /health turns red when fewer than 2 months are created ahead.
# - Every DDL statement runs with lock_timeout LOCK_TIMEOUT and is tried TRIES times, so a query on the parent waits at
#   most that long behind one attempt. Work that cannot get its lock is left for the next hourly run.
# - Nothing here runs DDL while pg_dump is dumping this database (maintain!): the dump holds a lock on every table
#   for as long as it runs.
# - Audit partitions are only ever created, each with its own truncate guard (a statement trigger is not cloned to
#   partitions). detach_and_drop! refuses them, and no other code path detaches or drops a partition.
module Partitions
  # append_only: the audit log's rules (no default partition, never detached or dropped, a truncate guard on every
  # partition calling <name>_append_only()).
  Table = Data.define(:name, :key, :width, :default, :append_only) do
    def audit? = append_only
    def truncate_guard = "#{name}_partition_no_truncate"
    def ahead_span(now) = width == :month ? now.advance(months: AHEAD) - now : AHEAD * (width == :day ? 1.day : 7.days)
  end

  # A partition of a table: from is nil for the legacy partition (MINVALUE); both are nil for the default.
  Partition = Data.define(:name, :from, :to) do
    def default? = to.nil?
    def legacy? = !default? && from.nil?
  end

  # A problem /health and `bin/rails partitions:status` report: severity :warning or :failing.
  Problem = Data.define(:severity, :text)

  # Raised when a DDL statement did not get its lock in TRIES attempts.
  class Busy < StandardError; end

  AUDIT = "audit_entries".freeze
  TABLES = [
    Table.new(name: "inventory_report_receipts", key: "received_at", width: :day, default: true, append_only: false),
    Table.new(name: "config_report_receipts", key: "received_at", width: :day, default: true, append_only: false),
    Table.new(name: "package_report_receipts", key: "received_at", width: :day, default: true, append_only: false),
    Table.new(name: "inventory_snapshots", key: "stored_at", width: :week, default: true, append_only: false),
    Table.new(name: "config_snapshots", key: "stored_at", width: :week, default: true, append_only: false),
    Table.new(name: "package_snapshots", key: "stored_at", width: :week, default: true, append_only: false),
    Table.new(name: "host_status_events", key: "stored_at", width: :week, default: true, append_only: false),
    Table.new(name: "cis_result_changes", key: "occurred_at", width: :week, default: true, append_only: false),
    Table.new(name: AUDIT, key: "occurred_at", width: :month, default: false, append_only: true)
  ].index_by(&:name).freeze

  AHEAD = 3
  # Fewer partitions ahead than this is a warning (for the audit log, a failure: it has no default to fall back on).
  MIN_AHEAD = 2
  # A partition due for retirement, or one ahead that is missing, for this long is a warning.
  OVERDUE = 3.days
  LONG_WINDOW = 180.days
  LONG_WIDTH = 30.days
  LOCK_TIMEOUT = "150ms".freeze
  TRIES = 3
  AUDIT_EVENT_TRIGGERS = %w[fleet_audit_guard_drop fleet_audit_guard_ddl].freeze
  # The columns the nightly check follows to their table, as the foreign keys did before.
  REFERENCES = {
    "inventory_report_receipts" => { "host_id" => "hosts" },
    "config_report_receipts" => { "host_id" => "hosts" },
    "package_report_receipts" => { "host_id" => "hosts" },
    "inventory_snapshots" => { "host_id" => "hosts" },
    "config_snapshots" => { "host_id" => "hosts" },
    "package_snapshots" => { "host_id" => "hosts" },
    "host_status_events" => { "host_id" => "hosts" },
    "cis_result_changes" => { "host_id" => "hosts", "cis_rule_id" => "cis_rules", "cis_rule_version_id" => "cis_rule_versions" }
  }.freeze

  # Seconds between tries of a DDL statement (specs set 0).
  mattr_accessor :pause, default: 1

  class << self
    def table(name) = name.is_a?(Table) ? name : TABLES.fetch(name.to_s)

    # The hourly maintenance (PartitionMaintenanceJob): partitions ahead, then Retention retires what has expired.
    # Does nothing while a backup of this database runs. Returns { "created" => {...}, "retired" => {...} }.
    def maintain!(now: Time.current, dry_run: false)
      if backup_running?
        Rails.logger.info("[partitions] a backup of this database is running: no partition maintenance this hour")
        return { "skipped" => "backup running" }
      end

      created = dry_run ? {} : ensure!(now:)
      { "created" => created, "retired" => Retention.retire!(now:, dry_run:) }
    end

    # Creates every table's default partition and its partitions up to AHEAD of now, and back to `from` when given
    # (the benchmark seed and specs write history in the past), moving any rows a new range finds in the default.
    # Tables not converted yet are skipped. `tables` limits it to some tables. Returns { table => [created names] }.
    def ensure!(now: Time.current, from: nil, tables: TABLES.keys)
      TABLES.values_at(*tables).to_h do |table|
        next [ table.name, [] ] unless partitioned?(table.name)

        [ table.name, ensure_table(table, now:, from:) ]
      rescue Busy => e
        Rails.logger.warn("[partitions] #{table.name}: #{e.message}; the next run tries again")
        [ table.name, [] ]
      end.tap do |created|
        made = created.reject { |_, names| names.empty? }
        Rails.logger.info("[partitions] created #{made.map { |t, names| "#{t}=#{names.size}" }.join(' ')}") if made.any?
      end
    end

    def partitioned?(name)
      connection.select_value("SELECT relkind FROM pg_class WHERE oid = to_regclass(#{connection.quote("public.#{name}")})") == "p"
    end

    # Every partition of the table, oldest first, the default (if any) last.
    def list(name)
      rows = connection.select_rows(<<~SQL.squish)
        SELECT c.relname, pg_get_expr(c.relpartbound, c.oid) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = #{connection.quote("public.#{name}")}::regclass
      SQL
      rows.map { |relname, bound| parse(relname, bound) }.sort_by { |p| [ p.default? ? 1 : 0, p.from || Time.at(0).utc ] }
    end

    def legacy(name) = list(name).find(&:legacy?)

    # Detaches a partition, then drops it, each in its own transaction under the lock timeout. Never an audit
    # partition: the audit log is never pruned (FR-S.3, ADR 0027 decision 7).
    def detach_and_drop!(name, partition)
      raise ArgumentError, "audit partitions are never detached or dropped (FR-S.3)" if table(name).audit?

      with_lock_timeout { |c| c.execute("ALTER TABLE #{c.quote_table_name(name)} DETACH PARTITION #{c.quote_table_name(partition.name)}") }
      with_lock_timeout { |c| c.execute("DROP TABLE #{c.quote_table_name(partition.name)}") }
    end

    # Drops partitions an earlier run detached but could not drop (the drop is a transaction of its own).
    def drop_leftovers!(name)
      raise ArgumentError, "audit partitions are never detached or dropped (FR-S.3)" if table(name).audit?

      leftovers = connection.select_values(<<~SQL.squish)
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relispartition
          AND (c.relname ~ #{connection.quote("^#{name}_p[0-9]{8}$")} OR c.relname = #{connection.quote("#{name}_legacy")})
      SQL
      leftovers.each { |relname| with_lock_timeout { |c| c.execute("DROP TABLE #{c.quote_table_name(relname)}") } }
      leftovers
    end

    # A session of pg_dump is dumping this database (its application_name, which any role can see).
    def backup_running?
      connection.execute("SELECT pg_stat_clear_snapshot()") # within a transaction the activity view is read once, then cached
      connection.select_value(<<~SQL.squish)
        SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = 'pg_dump' AND datname = current_database() AND pid <> pg_backend_pid())
      SQL
    end

    # What /health reports: :failing when the audit log has fewer than MIN_AHEAD months ahead (its writes would fail),
    # :warning for any other problem, otherwise :ok. Each problem is logged.
    def health(now: Time.current)
      found = problems(now:)
      found.each { |problem| Rails.logger.warn("[health] partitions: #{problem.text}") }
      return :ok if found.empty?

      found.any? { |problem| problem.severity == :failing } ? :failing : :warning
    end

    def problems(now: Time.current)
      TABLES.each_value.select { |table| partitioned?(table.name) }.flat_map { |table| table_problems(table, now) }
    end

    # The hardened audit guard (ops/postgres/audit-guard.sql) is installed: both event triggers enabled, and the
    # guard function owned by a superuser. /health shows a warning, not a failure, without it.
    def audit_guard_installed?
      connection.select_value(<<~SQL.squish)
        SELECT (SELECT count(*) FROM pg_event_trigger WHERE evtname IN (#{AUDIT_EVENT_TRIGGERS.map { |n| connection.quote(n) }.join(', ')}) AND evtenabled <> 'D') = #{AUDIT_EVENT_TRIGGERS.size}
           AND (SELECT r.rolsuper FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE p.oid = 'public.audit_entries_append_only()'::regprocedure)
      SQL
    end

    # The nightly check (PartitionCheckJob, `bin/rails partitions:check`): rows whose host, rule, or rule version does
    # not exist, in the partitions written since the last check (the default, the current, and the previous one of each
    # table), since these tables have no foreign keys. Returns { "table.column" => count } for the ones found.
    def orphans(now: Time.current)
      REFERENCES.each_with_object({}) do |(name, columns), found|
        next unless partitioned?(name)

        recent(table(name), now).each do |partition|
          columns.each do |column, referenced|
            count = connection.select_value(<<~SQL.squish).to_i
              SELECT count(*) FROM #{connection.quote_table_name(partition.name)} x
              WHERE x.#{column} IS NOT NULL AND NOT EXISTS (SELECT 1 FROM #{referenced} r WHERE r.id = x.#{column})
            SQL
            found["#{name}.#{column}"] = found.fetch("#{name}.#{column}", 0) + count if count.positive?
          end
        end
      end
    end

    # Runs the block in a transaction (a savepoint inside one) with lock_timeout set, TRIES times when the lock is not
    # granted. Raises Busy after the last try.
    def with_lock_timeout(tries: TRIES, timeout: LOCK_TIMEOUT)
      attempt = 0
      begin
        attempt += 1
        ApplicationRecord.transaction(requires_new: true) do
          connection.execute("SET LOCAL lock_timeout = #{connection.quote(timeout)}")
          yield connection
        end
      rescue ActiveRecord::LockWaitTimeout
        raise Busy, "lock not granted in #{tries} tries of #{timeout}" if attempt >= tries

        sleep pause
        retry
      end
    end

    # The partition holding a time: its first and last instant, by the table's width.
    def align(table, time)
      time = time.utc
      case table.width
      when :day then time.beginning_of_day
      when :week then time.beginning_of_week(:monday)
      else time.beginning_of_month
      end
    end

    # A lambda (start, direction) giving the next (1) or previous (-1) partition boundary of the table.
    def width_step(table)
      case table.width
      when :day then ->(t, dir) { t + dir.days }
      when :month then ->(t, dir) { t.advance(months: dir) }
      else
        days = Setting.retention_window > LONG_WINDOW ? LONG_WIDTH : 7.days
        ->(t, dir) { t + (dir * days) }
      end
    end

    private

    def connection = ApplicationRecord.connection

    def parse(relname, bound)
      return Partition.new(name: relname, from: nil, to: nil) if bound == "DEFAULT"

      from, to = bound.scan(/\((MINVALUE|'[^']+')\)/).flatten.map { |v| v == "MINVALUE" ? nil : Time.find_zone("UTC").parse(v.delete("'")) }
      Partition.new(name: relname, from:, to:)
    end

    def ensure_table(table, now:, from:)
      created = []
      parts = list(table.name)
      created << create_default(table) if table.default && parts.none?(&:default?)
      ranged = parts.reject(&:default?)
      oldest_default = table.default ? default_bounds(table).first : nil
      back_to = [ from, oldest_default ].compact.min
      step = width_step(table)

      cursor = ranged.map(&:to).max || align(table, back_to || now)
      if ranged.any? && back_to && (first = ranged.first.from) && back_to < first
        start = first
        while start > back_to
          before = step.call(start, -1)
          created << create_partition(table, before, start)
          start = before
        end
      end
      limit = now + table.ahead_span(now)
      while cursor <= limit
        after = step.call(cursor, 1)
        created << create_partition(table, cursor, after)
        cursor = after
      end
      created
    end

    def default_bounds(table)
      c = connection
      c.select_rows("SELECT min(#{table.key}), max(#{table.key}) FROM #{c.quote_table_name("#{table.name}_default")}").first.map do |v|
        v && Time.find_zone("UTC").parse(v.to_s)
      end
    end

    def create_default(table)
      name = "#{table.name}_default"
      with_lock_timeout { |c| c.execute("CREATE TABLE #{c.quote_table_name(name)} PARTITION OF #{c.quote_table_name(table.name)} DEFAULT") }
      name
    end

    # Creates the partition for [from, to). Rows the default holds in that range move into it in the same transaction
    # (PostgreSQL refuses a partition whose range has rows in the default).
    def create_partition(table, from, to)
      name = "#{table.name}_p#{from.strftime('%Y%m%d')}"
      with_lock_timeout do |c|
        parent = c.quote_table_name(table.name)
        range = "#{table.key} >= #{c.quote(from)} AND #{table.key} < #{c.quote(to)}"
        moving = table.default && c.select_value("SELECT 1 FROM #{c.quote_table_name("#{table.name}_default")} WHERE #{range} LIMIT 1")
        if moving
          c.execute("CREATE TEMP TABLE partition_rows (LIKE #{parent}) ON COMMIT DROP")
          c.execute("WITH moved AS (DELETE FROM #{c.quote_table_name("#{table.name}_default")} WHERE #{range} RETURNING *) INSERT INTO partition_rows SELECT * FROM moved")
        end
        c.execute("CREATE TABLE #{c.quote_table_name(name)} PARTITION OF #{parent} FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(to)})")
        if table.audit?
          c.execute("CREATE TRIGGER #{table.truncate_guard} BEFORE TRUNCATE ON #{c.quote_table_name(name)} FOR EACH STATEMENT EXECUTE FUNCTION #{table.name}_append_only()")
        end
        if moving
          c.execute("INSERT INTO #{parent} SELECT * FROM partition_rows")
          c.execute("DROP TABLE partition_rows")
        end
      end
      name
    end

    def table_problems(table, now)
      parts = list(table.name)
      ranged = parts.reject(&:default?)
      found = []
      default = parts.find(&:default?)
      if default && connection.select_value("SELECT EXISTS (SELECT 1 FROM #{connection.quote_table_name(default.name)})")
        found << Problem.new(severity: :warning, text: "#{table.name}: the default partition has rows (the next maintenance run moves them)")
      end
      ahead = ranged.count { |p| p.from && p.from > now }
      if ahead < MIN_AHEAD
        severity = table.audit? ? :failing : :warning
        found << Problem.new(severity:, text: "#{table.name}: #{ahead} partitions created ahead, fewer than #{MIN_AHEAD}")
      end
      covered = ranged.map(&:to).max
      if covered.nil? || covered < now + table.ahead_span(now) - OVERDUE
        found << Problem.new(severity: :warning, text: "#{table.name}: a partition ahead has been missing for #{OVERDUE.inspect}")
      end
      cutoff = Retention.cutoff_for(table.name, now:)
      if cutoff && ranged.any? { |p| p.to <= cutoff - OVERDUE }
        found << Problem.new(severity: :warning, text: "#{table.name}: a partition has been due for retirement for #{OVERDUE.inspect}")
      end
      found
    end

    # The default, and the partitions holding the last two widths up to now. Not the legacy partition: its rows were
    # written under the foreign keys.
    def recent(table, now)
      since = width_step(table).call(align(table, now), -1)
      list(table.name).select { |p| p.default? || (!p.legacy? && p.to > since && p.from <= now) }
    end
  end
end
