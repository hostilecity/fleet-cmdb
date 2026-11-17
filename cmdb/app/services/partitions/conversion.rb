module Partitions
  # Converts an existing table into a partitioned one without copying a row (ADR 0027, "Migration from the current
  # schema, online, at a million hosts"). The old table becomes the partition <table>_legacy, holding everything before
  # a cutover; the migrations in db/migrate (2026111619500x) run one conversion per table.
  #
  # 1. A new parent (<table>_new) with the old table's columns, defaults, and checks, its primary key (id, key), its
  #    indexes, its partitions from the cutover on, and a default (not for the audit log). No lock on the old table.
  # 2. The old table is prepared without blocking writes: a stored_at column with the constant default 2000-01-01 (a
  #    catalog-only change) where the key is stored_at; CREATE UNIQUE INDEX CONCURRENTLY on (id, key), and a
  #    non-unique twin of every unique index that lacks the key; a CHECK (key < cutover), added NOT VALID and then
  #    validated (which takes only a SHARE UPDATE EXCLUSIVE lock).
  # 3. The swap, one short transaction under a lock timeout, retried: the old table's primary key is replaced by the
  #    new unique index, unique indexes that lack the key are dropped, the tables and indexes are renamed, the sequence
  #    moves to the new parent, and the old table is attached as FROM (MINVALUE) TO (cutover). The validated CHECK lets
  #    PostgreSQL skip the scan, so the swap costs the same at any size.
  #
  # The cutover: for a stored_at table every old row has stored_at 2000-01-01, so it is the start of the current
  # partition and new rows go to the new partitions at once. For the others, rows keep arriving with their key at
  # "now" until the swap, so it is the first boundary at least a day away (an insert past it would break the CHECK).
  #
  # Every step can run again: a conversion that failed part-way (a lock not granted) is simply run again, and a table
  # already partitioned is left alone. Foreign keys must be gone first (drop_foreign_keys!): with them, every
  # partition operation would lock the referenced table.
  class Conversion
    LOCK_TIMEOUT = "500ms".freeze
    TRIES = 20
    STORED_AT_BEFORE = "2000-01-01".freeze

    # Drops every foreign key out of or into the tables, one short statement each under a lock timeout. Returns the
    # names dropped.
    def self.drop_foreign_keys!(tables, timeout: LOCK_TIMEOUT, tries: TRIES)
      c = ApplicationRecord.connection
      names = tables.map { |t| c.quote("public.#{t}") }.join(", ")
      keys = c.select_rows(<<~SQL.squish)
        SELECT conrelid::regclass::text, conname FROM pg_constraint
        WHERE contype = 'f' AND (conrelid = ANY (ARRAY[#{names}]::regclass[]) OR confrelid = ANY (ARRAY[#{names}]::regclass[]))
        ORDER BY 1, 2
      SQL
      keys.each do |table, name|
        Partitions.with_lock_timeout(timeout:, tries:) { c.execute("ALTER TABLE #{c.quote_table_name(table)} DROP CONSTRAINT #{c.quote_column_name(name)}") }
      end
      keys.map(&:last)
    end

    attr_reader :cutover

    # name: a table in Partitions::TABLES, or a Partitions::Table.
    def initialize(name, now: Time.current, timeout: LOCK_TIMEOUT, tries: TRIES)
      @table = Partitions.table(name)
      @name = @table.name
      @key = @table.key
      @now = now
      @timeout = timeout
      @tries = tries
      @c = ApplicationRecord.connection
    end

    # Returns :converted, or :already when the table was partitioned before.
    def run!
      return :already if Partitions.partitioned?(@name)

      refuse_foreign_keys!
      @cutover = cutover_time
      ddl("ALTER TABLE #{q(@name)} DROP CONSTRAINT IF EXISTS #{q(range_check)}")
      ddl("ALTER TABLE #{q(@name)} ADD COLUMN IF NOT EXISTS stored_at timestamp(6) NOT NULL DEFAULT #{@c.quote(STORED_AT_BEFORE)}") if stored_at?
      build_parent
      build_legacy_indexes
      ddl("ALTER TABLE #{q(@name)} ADD CONSTRAINT #{q(range_check)} CHECK (#{@key} < #{@c.quote(@cutover)}) NOT VALID")
      @c.execute("ALTER TABLE #{q(@name)} VALIDATE CONSTRAINT #{q(range_check)}")
      swap
      @c.execute("ANALYZE #{q(@name)}")
      :converted
    end

    private

    def q(name) = @c.quote_table_name(name)
    def stored_at? = @key == "stored_at"
    def new_parent = "#{@name}_new"
    def legacy = "#{@name}_legacy"
    def range_check = "#{@name}_legacy_range"
    def legacy_pkey = "#{@name}_legacy_pkey"
    def guard = "#{@name}_append_only" # the append-only guard function of an audit-like table

    def ddl(sql) = Partitions.with_lock_timeout(timeout: @timeout, tries: @tries) { |c| c.execute(sql) }

    def refuse_foreign_keys!
      count = @c.select_value(<<~SQL.squish)
        SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND (conrelid = #{@c.quote("public.#{@name}")}::regclass OR confrelid = #{@c.quote("public.#{@name}")}::regclass)
      SQL
      raise ArgumentError, "#{@name} still has foreign keys: drop them first (Partitions::Conversion.drop_foreign_keys!)" if count.positive?
    end

    def cutover_time
      step = Partitions.width_step(@table)
      return Partitions.align(@table, @now) if stored_at?

      soonest = @now + 1.day
      start = Partitions.align(@table, soonest)
      start < soonest ? step.call(start, 1) : start
    end

    # The old table's indexes other than its primary key and the ones this conversion builds: name, definition, and
    # whether it is unique without the partition key (so the parent gets a plain index and the legacy table a twin).
    def old_indexes
      @old_indexes ||= @c.select_rows(<<~SQL.squish).map do |name, definition, unique, columns|
        SELECT ic.relname, pg_get_indexdef(x.indexrelid), x.indisunique,
               array_to_string(ARRAY(SELECT a.attname FROM pg_attribute a WHERE a.attrelid = x.indrelid AND a.attnum = ANY (x.indkey)), ',')
        FROM pg_index x JOIN pg_class ic ON ic.oid = x.indexrelid
        WHERE x.indrelid = #{@c.quote("public.#{@name}")}::regclass AND NOT x.indisprimary AND ic.relname NOT LIKE #{@c.quote("#{legacy}%")}
        ORDER BY ic.relname
      SQL
        { name:, definition:, plain: unique && !columns.split(",").include?(@key) }
      end
    end

    # The definition on another table under another name, unique or not.
    def definition_for(index, table:, name:, unique:)
      index[:definition].sub(/\ACREATE (UNIQUE )?INDEX \S+ ON (ONLY )?public\.\S+ /, "CREATE #{'UNIQUE ' if unique}INDEX #{q(name)} ON public.#{q(table)} ")
    end

    def build_parent
      @c.execute("DROP TABLE IF EXISTS #{q(new_parent)} CASCADE") # a parent left by a run that failed before its swap
      @c.execute("CREATE TABLE #{q(new_parent)} (LIKE #{q(@name)} INCLUDING DEFAULTS INCLUDING CONSTRAINTS) PARTITION BY RANGE (#{@key})")
      @c.execute("ALTER TABLE #{q(new_parent)} ALTER COLUMN stored_at SET DEFAULT now()") if stored_at?
      @c.execute("ALTER TABLE #{q(new_parent)} ADD CONSTRAINT #{q("#{new_parent}_pkey")} PRIMARY KEY (id, #{@key})")
      old_indexes.each_with_index do |index, i|
        @c.execute(definition_for(index, table: new_parent, name: "#{new_parent}_i#{i}", unique: !index[:plain] && index[:definition].start_with?("CREATE UNIQUE")))
      end
      if @table.audit?
        @c.execute("CREATE TRIGGER #{@name}_no_update_or_delete BEFORE UPDATE OR DELETE ON #{q(new_parent)} FOR EACH ROW EXECUTE FUNCTION #{guard}()")
        @c.execute("CREATE TRIGGER #{@name}_no_truncate BEFORE TRUNCATE ON #{q(new_parent)} FOR EACH STATEMENT EXECUTE FUNCTION #{guard}()")
      end
      @c.execute("CREATE TABLE #{q("#{@name}_default")} PARTITION OF #{q(new_parent)} DEFAULT") if @table.default
      step = Partitions.width_step(@table)
      from = @cutover
      limit = @now + @table.ahead_span(@now)
      while from <= limit
        to = step.call(from, 1)
        partition = "#{@name}_p#{from.strftime('%Y%m%d')}"
        @c.execute("CREATE TABLE #{q(partition)} PARTITION OF #{q(new_parent)} FOR VALUES FROM (#{@c.quote(from)}) TO (#{@c.quote(to)})")
        if @table.audit?
          @c.execute("CREATE TRIGGER #{@table.truncate_guard} BEFORE TRUNCATE ON #{q(partition)} FOR EACH STATEMENT EXECUTE FUNCTION #{guard}()")
        end
        from = to
      end
    end

    # The unique (id, key) index that becomes the legacy partition's primary key, and a plain twin of each unique index
    # without the key, both built without blocking writes. One left invalid by an interrupted build is built again.
    def build_legacy_indexes
      wanted = { legacy_pkey => "CREATE UNIQUE INDEX CONCURRENTLY #{q(legacy_pkey)} ON #{q(@name)} (id, #{@key})" }
      old_indexes.each_with_index do |index, i|
        next unless index[:plain]

        wanted["#{legacy}_c#{i}"] = definition_for(index, table: @name, name: "#{legacy}_c#{i}", unique: false).sub("CREATE INDEX", "CREATE INDEX CONCURRENTLY")
      end
      wanted.each do |name, sql|
        valid = @c.select_value("SELECT x.indisvalid FROM pg_index x JOIN pg_class c ON c.oid = x.indexrelid WHERE c.relname = #{@c.quote(name)}")
        next if valid

        @c.execute("DROP INDEX CONCURRENTLY IF EXISTS #{q(name)}") unless valid.nil?
        @c.execute(sql)
      end
    end

    def swap
      if !stored_at? && Time.current >= @cutover
        raise "the cutover #{@cutover.utc.iso8601} has passed: run the conversion of #{@name} again"
      end

      sequence = @c.select_value("SELECT pg_get_serial_sequence(#{@c.quote("public.#{@name}")}, 'id')")
      pkey = @c.select_value("SELECT conname FROM pg_constraint WHERE conrelid = #{@c.quote("public.#{@name}")}::regclass AND contype = 'p'")
      Partitions.with_lock_timeout(timeout: @timeout, tries: @tries) do |c|
        c.execute("LOCK TABLE #{q(@name)} IN ACCESS EXCLUSIVE MODE")
        if @table.audit?
          # The parent's row trigger is cloned to the legacy partition when it is attached; its statement trigger is not,
          # so the old one stays, renamed as every audit partition's truncate guard.
          c.execute("DROP TRIGGER #{@name}_no_update_or_delete ON #{q(@name)}")
          c.execute("ALTER TRIGGER #{@name}_no_truncate ON #{q(@name)} RENAME TO #{@table.truncate_guard}")
        end
        c.execute("ALTER TABLE #{q(@name)} DROP CONSTRAINT #{q(pkey)}")
        c.execute("ALTER TABLE #{q(@name)} ADD CONSTRAINT #{q(legacy_pkey)} PRIMARY KEY USING INDEX #{q(legacy_pkey)}")
        old_indexes.each_with_index do |index, i|
          c.execute(index[:plain] ? "DROP INDEX #{q(index[:name])}" : "ALTER INDEX #{q(index[:name])} RENAME TO #{q("#{legacy}_#{i}")}")
        end
        c.execute("ALTER SEQUENCE #{sequence} OWNED BY #{q(new_parent)}.id")
        c.execute("ALTER TABLE #{q(@name)} RENAME TO #{q(legacy)}")
        c.execute("ALTER TABLE #{q(new_parent)} RENAME TO #{q(@name)}")
        c.execute("ALTER TABLE #{q(@name)} RENAME CONSTRAINT #{q("#{new_parent}_pkey")} TO #{q(pkey)}")
        old_indexes.each_with_index { |index, i| c.execute("ALTER INDEX #{q("#{new_parent}_i#{i}")} RENAME TO #{q(index[:name])}") }
        c.execute("ALTER TABLE #{q(@name)} ATTACH PARTITION #{q(legacy)} FOR VALUES FROM (MINVALUE) TO (#{c.quote(@cutover)})")
        c.execute("ALTER TABLE #{q(legacy)} DROP CONSTRAINT #{q(range_check)}")
      end
    end
  end
end
