# Prunes history older than the retention window (NFR-2, DEC-07, P1-S10): inventory, package, and config snapshots,
# recent report ids, CIS result changes, host status events, report requests, and advisory refresh attempts, 90 days by default
# (Setting "retention.days"). Current results (CisResult) are not history and are never pruned.
#
# - The tables registered with `partitioned: true` are partitioned by time (ADR 0027, #195, Partitions). retire!
#   (hourly, PartitionMaintenanceJob) drops each of their partitions whose whole range is past the window: one catalog
#   operation instead of a delete per row. So a row is kept for the window plus up to one partition width (a day of
#   receipts, a week of the rest): "at least" the window. prune! (daily, RetentionPruneJob) still deletes rows one
#   batch at a time inside a table's legacy partition (the rows from before the table was partitioned) until that
#   partition can be retired too, and in the tables that are not partitioned.
# - The newest row per host survives for the tables registered with `keep_newest_per_host`, whatever its age,
#   so a host that stopped reporting still shows its last snapshot and last status change. Before partitions are
#   retired, each host's newest row in them, for every host with no row in a partition that stays, is moved forward to
#   the current partition (UPDATE of stored_at, which keeps its id), in batches of `batch_size`, each its own
#   transaction.
# - The newest row of the whole table survives for the tables registered with `keep_newest`, whatever its age:
#   the last advisory refresh attempt holds the cool-down (P2-S15), which can be longer than the window (review
#   of #125).
# - Advisory and triage import records, and the current triage entries, are not history: freshness is read from the
#   imports, so they are kept however old (P2-D06, P2-S16), and the entries are replaced only by an import.
# - Audit entries are never pruned (FR-S.3). They are not registered here, the partition code never detaches or drops
#   an audit partition, and the database blocks deleting them anyway.
# - Report ids (the receipts that recognise a retried report) are kept for REPORT_ID_WINDOW, or the retention window
#   if it is shorter: they only need to outlive an agent's retries, and an agent writes one for every report (96
#   inventory reports a day), so at 90 days they were the largest table of all (about 9,400 rows a host). A report
#   retried after its receipt is gone is processed again as a new report: it writes a snapshot only if its content
#   differs from the host's stored state, as any report does.
# - Deletes run in batches of `batch_size` rows, each its own short statement, so a large table never holds a
#   long lock or writes one huge transaction.
# - `dry_run` counts what would be deleted (or retired) and changes nothing.
# - A later phase registers its own snapshot type with Retention.register (for example P2-S12).
module Retention
  Target = Data.define(:model, :time_column, :keep_newest_per_host, :keep_newest, :only, :max_age, :partitioned)

  DEFAULT_BATCH_SIZE = 1_000
  # How long report ids are kept (see above): longer than any retry (an agent waits at most a day between retries).
  REPORT_ID_WINDOW = 7.days

  @targets = []

  class << self
    attr_reader :targets

    # Adds a table to prune. `time_column` is the row's age (received_at, occurred_at); `keep_newest_per_host`
    # needs a host_id column and an index on (host_id, time_column); `keep_newest` keeps the table's newest row;
    # `only` (a where condition) limits pruning to the rows that are history, such as resolved findings; `max_age`
    # prunes the table sooner than the retention window; `partitioned` says the table is in Partitions::TABLES (with
    # keep_newest_per_host, its partition key must be stored_at).
    def register(model, time_column:, keep_newest_per_host: false, keep_newest: false, only: nil, max_age: nil, partitioned: false)
      @targets.reject! { |target| target.model == model }
      @targets << Target.new(model:, time_column:, keep_newest_per_host:, keep_newest:, only:, max_age:, partitioned:)
    end

    # Deletes (or, in a dry run, counts) the expired rows of every target: of a partitioned table, only those in its
    # legacy partition. Returns { "inventory_snapshots" => 12 }.
    def prune!(now: Time.current, window: Setting.retention_window, dry_run: false, batch_size: DEFAULT_BATCH_SIZE)
      cutoff = now - window
      counts = targets.to_h do |target|
        [ target.model.table_name, prune_target(target, cutoff: cutoff(target, now:, window:), dry_run:, batch_size:) ]
      end
      summary = counts.map { |table, count| "#{table}=#{count}" }.join(" ")
      sooner = targets.filter_map { |t| "#{t.model.table_name} older than #{(now - t.max_age).utc.iso8601}" if t.max_age && t.max_age < window }
      Rails.logger.info("[retention] #{dry_run ? 'dry run, would delete' : 'deleted'} #{summary} older than #{cutoff.utc.iso8601}" \
                        "#{" (#{sooner.join(', ')})" if sooner.any?}")
      counts
    end

    # Retires (detaches and drops) every partition of a partitioned target whose whole range is at or before the
    # target's cutoff, the legacy partition included once its cutover is, after moving each host's newest row forward
    # where the newest is kept. Returns { "inventory_snapshots" => { "partitions" => 2, "rows" => 4100, "moved" => 30 } }.
    # rows is PostgreSQL's estimate of the rows dropped (exact in a dry run, which counts and changes nothing).
    # still_held is the partition maintenance lock's check (Partitions.maintain!, #198), called before each batch moved
    # forward and each drop; a run outside the lock checks nothing.
    def retire!(now: Time.current, window: Setting.retention_window, dry_run: false, batch_size: DEFAULT_BATCH_SIZE, still_held: Partitions::UNCHECKED)
      results = targets.select(&:partitioned).to_h do |target|
        [ target.model.table_name, retire_target(target, cutoff: cutoff(target, now:, window:), now:, dry_run:, batch_size:, still_held:) ]
      rescue Partitions::Busy => e
        Rails.logger.warn("[retention] #{target.model.table_name}: #{e.message}; the next run tries again")
        [ target.model.table_name, { "partitions" => 0, "rows" => 0, "moved" => 0 } ]
      end
      done = results.reject { |_, r| r["partitions"].zero? }
      if done.any? || dry_run
        summary = done.map { |table, r| "#{table}=#{r['partitions']} (#{r['rows']} rows, #{r['moved']} moved forward)" }.join(" ")
        Rails.logger.info("[retention] #{dry_run ? 'dry run, would retire' : 'retired'} partitions #{summary.presence || 'none'}")
      end
      results
    end

    # When a partitioned table's rows expire (nil for a table that is not a target, such as the audit log).
    def cutoff_for(table_name, now: Time.current, window: Setting.retention_window)
      target = targets.find { |t| t.model.table_name == table_name }
      target && cutoff(target, now:, window:)
    end

    private

    def cutoff(target, now:, window:) = now - [ window, target.max_age ].compact.min

    def prune_target(target, cutoff:, dry_run:, batch_size:)
      partitioned = target.partitioned && Partitions.partitioned?(target.model.table_name)
      legacy = partitioned && Partitions.legacy(target.model.table_name)
      return 0 if partitioned && !legacy

      expired = expired_scope(target, cutoff, from: legacy)
      return expired.count if dry_run

      total = 0
      loop do
        batch = target.model.where(id: expired.limit(batch_size).select(:id))
        # The partition key bounds the delete to the legacy partition.
        batch = batch.where(target.model.arel_table[Partitions.table(target.model.table_name).key].lt(legacy.to)) if legacy
        deleted = batch.delete_all
        total += deleted
        break if deleted < batch_size
      end
      total
    end

    # The expired rows of the table, or of one of its partitions (`from`), read under the table's own name.
    def expired_scope(target, cutoff, from: nil)
      table = target.model.quoted_table_name
      column = target.model.connection.quote_column_name(target.time_column)
      scope = target.model.all
      scope = scope.from("#{target.model.connection.quote_table_name(from.name)} #{table}") if from
      scope = scope.where("#{table}.#{column} < ?", cutoff)
      scope = scope.where(target.only) if target.only
      if target.keep_newest
        scope = scope.where("EXISTS (SELECT 1 FROM #{table} newer WHERE (newer.#{column}, newer.id) > (#{table}.#{column}, #{table}.id))")
      end
      return scope unless target.keep_newest_per_host

      # Not the newest row of its host: a row with the same host and a later time (or the same time and a
      # higher id) exists, in any partition. The (host_id, time) index serves the lookup.
      scope.where(<<~SQL.squish)
        EXISTS (SELECT 1 FROM #{table} newer
                WHERE newer.host_id = #{table}.host_id
                  AND (newer.#{column}, newer.id) > (#{table}.#{column}, #{table}.id))
      SQL
    end

    def retire_target(target, cutoff:, now:, dry_run:, batch_size:, still_held:)
      name = target.model.table_name
      result = { "partitions" => 0, "rows" => 0, "moved" => 0 }
      return result unless Partitions.partitioned?(name)

      Partitions.drop_leftovers!(name, still_held:) unless dry_run
      # The chain is contiguous, so the partitions due are every partition before a boundary.
      due = Partitions.list(name).reject(&:default?).select { |p| p.to <= cutoff }
      return result if due.empty?

      kept = target.keep_newest_per_host ? newest_kept(target, due.last.to) : []
      result["moved"] = kept.size
      result["partitions"] = due.size
      result["rows"] = [ due.sum { |p| dry_run ? exact_rows(p) : estimated_rows(p) } - kept.size, 0 ].max
      return result if dry_run

      move_forward(target, due.last.to, kept, now:, batch_size:, still_held:)
      due.each { |partition| Partitions.detach_and_drop!(name, partition, still_held:) }
      result
    end

    # The ids of each host's newest row before the boundary (in the partitions being retired), for every host with no
    # row at or after it (in a partition that stays): the rows that must survive. Those partitions' ranges are past, so
    # no row is written to them meanwhile.
    def newest_kept(target, boundary)
      c = target.model.connection
      table = target.model.quoted_table_name
      key = Partitions.table(target.model.table_name).key
      column = c.quote_column_name(target.time_column)
      c.select_values(<<~SQL.squish)
        SELECT k.id FROM (SELECT DISTINCT ON (host_id) id, host_id FROM #{table} WHERE #{key} < #{c.quote(boundary)}
                          ORDER BY host_id, #{column} DESC, id DESC) k
        WHERE NOT EXISTS (SELECT 1 FROM #{table} n WHERE n.host_id = k.host_id AND n.#{key} >= #{c.quote(boundary)})
      SQL
    end

    # Moves the rows forward by setting stored_at to now: PostgreSQL moves a row whose partition key changes to the
    # partition it now belongs to, keeping its id. Through the parent, bounded to the partitions being retired.
    def move_forward(target, boundary, ids, now:, batch_size:, still_held:)
      c = target.model.connection
      ids.each_slice(batch_size) do |slice|
        still_held.call
        target.model.transaction(requires_new: true) do
          c.execute("UPDATE #{target.model.quoted_table_name} SET stored_at = #{c.quote(now)} WHERE stored_at < #{c.quote(boundary)} AND id IN (#{slice.join(',')})")
        end
      end
    end

    def exact_rows(partition) = ApplicationRecord.connection.select_value("SELECT count(*) FROM #{ApplicationRecord.connection.quote_table_name(partition.name)}").to_i

    def estimated_rows(partition)
      [ ApplicationRecord.connection.select_value("SELECT reltuples::bigint FROM pg_class WHERE relname = #{ApplicationRecord.connection.quote(partition.name)}").to_i, 0 ].max
    end
  end

  register InventorySnapshot, time_column: :received_at, keep_newest_per_host: true, partitioned: true
  register InventoryReportReceipt, time_column: :received_at, max_age: REPORT_ID_WINDOW, partitioned: true
  register PackageSnapshot, time_column: :received_at, keep_newest_per_host: true, partitioned: true
  register PackageReportReceipt, time_column: :received_at, max_age: REPORT_ID_WINDOW, partitioned: true
  register ConfigSnapshot, time_column: :received_at, keep_newest_per_host: true, partitioned: true
  register ConfigReportReceipt, time_column: :received_at, max_age: REPORT_ID_WINDOW, partitioned: true
  register CisResultChange, time_column: :occurred_at, partitioned: true
  register HostStatusEvent, time_column: :occurred_at, keep_newest_per_host: true, partitioned: true
  # On-demand report requests (P2-S03), by when they were made: a request ends within an hour, and the audit
  # log keeps who asked.
  register ReportRequest, time_column: :requested_at
  # When each advisory feed refresh started (P2-S15): only the newest matters, for the cool-down, and it is kept
  # however old, since the cool-down has no upper bound (review of #125).
  register AdvisoryRefreshAttempt, time_column: :started_at, keep_newest: true
  # Resolved vulnerability findings (P2-S12), by when they were resolved. Open and reopened findings are current state
  # and never pruned. If the same package and advisory match again after a resolved finding was pruned, the matcher
  # opens a new finding rather than reopening the old one.
  register VulnerabilityFinding, time_column: :resolved_at, only: { state: "resolved" }
end
