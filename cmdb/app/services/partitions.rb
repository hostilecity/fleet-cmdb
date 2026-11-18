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

  # The session advisory lock one maintenance run holds (maintain! and ensure!), so two never overlap: a boot-time
  # partitions:ensure, the hourly job, and a manual run. The loser does nothing and says so.
  LOCK_KEY = 195_027
  RETIRED = "_retired".freeze
  MOVING = "_default_moving".freeze
  # Rows the default partition holds are moved back through the parent this many at a time, each its own transaction.
  MOVE_BATCH = 1_000
  ORPHANS_KEY = "partitions/orphans".freeze
  REPORTED_KEY = "partitions/reported".freeze

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

      result = exclusively do
        created = dry_run ? {} : ensure!(now:)
        { "created" => created, "retired" => Retention.retire!(now:, dry_run:) }
      end
      return { "skipped" => "another maintenance run is in progress" } if result == :busy

      report_changes(run_problems(now:)) unless dry_run
      result
    end

    # Runs the block holding the maintenance lock, or returns :busy when another session holds it. Re-entrant within
    # one session (maintain! calls ensure!).
    def exclusively
      return :busy unless connection.select_value("SELECT pg_try_advisory_lock(#{LOCK_KEY})")

      begin
        yield
      ensure
        connection.select_value("SELECT pg_advisory_unlock(#{LOCK_KEY})")
      end
    end

    # Creates every table's default partition and its partitions up to AHEAD of now, and back to `from` when given
    # (the benchmark seed and specs write history in the past), moving any rows a new range finds in the default.
    # Tables not converted yet are skipped. `tables` limits it to some tables. Returns { table => [created names] }, or
    # nil when another maintenance run holds the lock.
    def ensure!(now: Time.current, from: nil, tables: TABLES.keys)
      result = exclusively do
        TABLES.values_at(*tables).to_h do |table|
          next [ table.name, [] ] unless partitioned?(table.name)

          [ table.name, ensure_table(table, now:, from:) ]
        rescue Busy => e
          Rails.logger.warn("[partitions] #{table.name}: #{e.message}; the next run tries again")
          [ table.name, [] ]
        end
      end
      if result == :busy
        Rails.logger.info("[partitions] another maintenance run is in progress: nothing done")
        return nil
      end

      made = result.reject { |_, names| names.empty? }
      Rails.logger.info("[partitions] created #{made.map { |t, names| "#{t}=#{names.size}" }.join(' ')}") if made.any?
      result
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

    # Detaches a partition and renames it <name>_retired, in one transaction under the lock timeout, then drops it in
    # another. Never an audit partition: the audit log is never pruned (FR-S.3, ADR 0027 decision 7).
    def detach_and_drop!(name, partition)
      raise ArgumentError, "audit partitions are never detached or dropped (FR-S.3)" if table(name).audit?

      retired = "#{partition.name}#{RETIRED}"
      with_lock_timeout do |c|
        c.execute("ALTER TABLE #{c.quote_table_name(name)} DETACH PARTITION #{c.quote_table_name(partition.name)}")
        c.execute("ALTER TABLE #{c.quote_table_name(partition.name)} RENAME TO #{c.quote_table_name(retired)}")
      end
      with_lock_timeout { |c| c.execute("DROP TABLE #{c.quote_table_name(retired)}") }
    end

    # Drops partitions an earlier run detached but could not drop (the drop is a transaction of its own): only the ones
    # this code detached, which it renamed <partition>_retired. A partition an operator detached keeps its name and is
    # left alone.
    def drop_leftovers!(name)
      raise ArgumentError, "audit partitions are never detached or dropped (FR-S.3)" if table(name).audit?

      leftovers = connection.select_values(<<~SQL.squish)
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relispartition
          AND c.relname ~ #{connection.quote("^#{name}_(p[0-9]{8}|legacy)#{RETIRED}$")}
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
    # :warning for any other problem (orphans found by the nightly check included), otherwise :ok. The hourly run logs
    # problems as they appear and clear (report_changes), not every request.
    def health(now: Time.current)
      found = problems(now:) + orphan_problems
      return :ok if found.empty?

      found.any? { |problem| problem.severity == :failing } ? :failing : :warning
    end

    def problems(now: Time.current)
      TABLES.each_value.select { |table| partitioned?(table.name) }.flat_map { |table| table_problems(table, now) }
    end

    # The hardened audit guard (ops/postgres/audit-guard.sql) holds. /health shows a warning, not a failure, without it.
    def audit_guard_installed? = audit_guard_problem.nil?

    # Why the audit guard does not hold, or nil when it does: the app's role, or the owner of audit_entries, is a
    # superuser (no guard holds against one); an event trigger is missing or disabled; the guard function is not the
    # superuser's; or a partition is not among the objects the guard protects (it was created while the guard was off).
    def audit_guard_problem
      c = connection
      return "the app's PostgreSQL role is a superuser, so no guard can hold against it" if c.select_value("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
      if c.select_value("SELECT r.rolsuper FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE c.oid = 'public.audit_entries'::regclass")
        return "audit_entries is owned by a PostgreSQL superuser, so no guard can hold against it"
      end
      enabled = c.select_value("SELECT count(*) FROM pg_event_trigger WHERE evtname IN (#{AUDIT_EVENT_TRIGGERS.map { |n| c.quote(n) }.join(', ')}) AND evtenabled <> 'D'")
      return "the audit log's event triggers are not installed (the superuser runs ops/postgres/audit-guard.sql)" if enabled < AUDIT_EVENT_TRIGGERS.size
      unless c.select_value("SELECT r.rolsuper FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE p.oid = 'public.audit_entries_append_only()'::regprocedure")
        return "the guard function audit_entries_append_only() is not owned by the superuser (run ops/postgres/audit-guard.sql)"
      end
      missing = c.select_values(<<~SQL.squish)
        SELECT t.relid::regclass::text FROM pg_partition_tree('public.audit_entries'::regclass) t
        WHERE NOT EXISTS (SELECT 1 FROM fleet_audit_guard.protected p WHERE p.objid = t.relid AND p.kind IN ('parent', 'partition'))
      SQL
      "#{missing.join(', ')} not protected by the audit guard (the superuser runs ops/postgres/audit-guard.sql again)" if missing.any?
    end

    # What an operator should look at, as sentences, for the banner on every dashboard page: what the last hourly run
    # found (partition problems and, in production, an audit guard that does not hold) and the rows the nightly check
    # found without their host or rule. Read from the cache those jobs write, so a page view runs no catalog query.
    def attention = (Rails.cache.read(REPORTED_KEY) || []) + orphan_problems.map(&:text)

    # What the hourly run found, for the banner: partition problems and, in production, an audit guard that does not hold.
    def run_problems(now: Time.current)
      found = problems(now:)
      if Rails.env.production? && (guard = audit_guard_problem)
        found << Problem.new(severity: :warning, text: "The audit log's guard does not hold: #{guard}.")
      end
      found
    end

    # Logs each problem when it appears, and once more when it clears, instead of on every /health request, and keeps
    # the list for the banner (two hours: an hourly run that stops reporting lets it lapse). The hourly run calls it.
    def report_changes(found)
      texts = found.map(&:text)
      before = Rails.cache.read(REPORTED_KEY) || []
      (texts - before).each { |text| Rails.logger.warn("[partitions] needs attention: #{text}") }
      (before - texts).each { |text| Rails.logger.info("[partitions] resolved: #{text}") }
      Rails.cache.write(REPORTED_KEY, texts, expires_in: 2.hours)
    end

    # The nightly check's last finding, kept two days, as problems.
    def orphan_problems
      (Rails.cache.read(ORPHANS_KEY) || {}).map do |column, count|
        Problem.new(severity: :warning, text: "#{column}: #{count} recent rows name a host or rule that does not exist (bin/rails partitions:check)")
      end
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
      limit = now + table.ahead_span(now)
      moving = table.default ? set_aside_default(table, limit + LONG_WIDTH + 1.day) : nil
      parts = list(table.name)
      created << create_default(table) if table.default && parts.none?(&:default?)
      ranged = parts.reject(&:default?)
      back_to = [ from, moving && bounds(moving, table.key).first ].compact.min
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
      while cursor <= limit
        after = step.call(cursor, 1)
        created << create_partition(table, cursor, after)
        cursor = after
      end
      move_back(table, moving) if moving
      created
    end

    # A default partition holding rows the partitions about to be created would cover (PostgreSQL refuses a partition
    # whose range has rows in the default) is detached and renamed <table>_default_moving, and an empty default takes
    # its place, all in one short transaction: no lock is held while its rows are copied (move_back). Returns that table's
    # name, or nil. One left by an interrupted run is picked up again.
    def set_aside_default(table, horizon)
      c = connection
      moving = "#{table.name}#{MOVING}"
      return moving if c.table_exists?(moving)

      default = "#{table.name}_default"
      return nil unless c.table_exists?(default) && c.select_value("SELECT 1 FROM #{c.quote_table_name(default)} WHERE #{table.key} < #{c.quote(horizon)} LIMIT 1")

      with_lock_timeout do
        c.execute("ALTER TABLE #{c.quote_table_name(table.name)} DETACH PARTITION #{c.quote_table_name(default)}")
        c.execute("ALTER TABLE #{c.quote_table_name(default)} RENAME TO #{c.quote_table_name(moving)}")
        c.execute("CREATE TABLE #{c.quote_table_name(default)} PARTITION OF #{c.quote_table_name(table.name)} DEFAULT")
      end
      moving
    end

    # Moves the set-aside default's rows back through the parent, MOVE_BATCH at a time, each batch its own short
    # transaction (only ROW EXCLUSIVE on the parent), into the partitions now created for them (rows past them go to
    # the new default), then drops it. Until a row is moved back, readers do not see it.
    def move_back(table, moving)
      c = connection
      loop do
        moved = ApplicationRecord.transaction(requires_new: true) do
          c.exec_update(<<~SQL.squish)
            WITH batch AS (DELETE FROM #{c.quote_table_name(moving)} WHERE ctid = ANY (ARRAY(SELECT ctid FROM #{c.quote_table_name(moving)} LIMIT #{MOVE_BATCH})) RETURNING *)
            INSERT INTO #{c.quote_table_name(table.name)} SELECT * FROM batch
          SQL
        end
        break if moved < MOVE_BATCH
      end
      with_lock_timeout { c.execute("DROP TABLE #{c.quote_table_name(moving)}") }
    end

    def bounds(relname, key)
      c = connection
      c.select_rows("SELECT min(#{key}), max(#{key}) FROM #{c.quote_table_name(relname)}").first.map { |v| v && Time.find_zone("UTC").parse(v.to_s) }
    end

    def create_default(table)
      name = "#{table.name}_default"
      with_lock_timeout { |c| c.execute("CREATE TABLE #{c.quote_table_name(name)} PARTITION OF #{c.quote_table_name(table.name)} DEFAULT") }
      name
    end

    # Creates the partition for [from, to). Its range holds no rows in the default: set_aside_default moved them out.
    def create_partition(table, from, to)
      name = "#{table.name}_p#{from.strftime('%Y%m%d')}"
      with_lock_timeout do |c|
        c.execute("CREATE TABLE #{c.quote_table_name(name)} PARTITION OF #{c.quote_table_name(table.name)} FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(to)})")
        # Its own truncate guard: a statement trigger is not cloned from the parent. Once the superuser's event trigger is
        # installed (ops/postgres/audit-guard.sql), it has already added one.
        if table.audit? && !c.select_value("SELECT 1 FROM pg_trigger WHERE tgrelid = #{c.quote(name)}::regclass AND tgname = #{c.quote(table.truncate_guard)}")
          c.execute("CREATE TRIGGER #{table.truncate_guard} BEFORE TRUNCATE ON #{c.quote_table_name(name)} FOR EACH STATEMENT EXECUTE FUNCTION #{table.name}_append_only()")
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
      if connection.table_exists?("#{table.name}#{MOVING}")
        found << Problem.new(severity: :warning, text: "#{table.name}: rows set aside from the default partition are still being moved back")
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
