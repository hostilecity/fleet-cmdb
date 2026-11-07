# Prunes history older than the retention window (NFR-2, DEC-07, P1-S10): inventory, package, and config snapshots,
# recent report ids, CIS result changes, host status events, report requests, and advisory refresh attempts, 90 days by default
# (Setting "retention.days"). Current results (CisResult) are not history and are never pruned.
#
# - The newest row per host survives for the tables registered with `keep_newest_per_host`, whatever its age,
#   so a host that stopped reporting still shows its last snapshot and last status change.
# - The newest row of the whole table survives for the tables registered with `keep_newest`, whatever its age:
#   the last advisory refresh attempt holds the cool-down (P2-S15), which can be longer than the window (review
#   of #125).
# - Audit entries are never pruned (FR-S.3). They are not registered here, and the database blocks deleting
#   them anyway.
# - Deletes run in batches of `batch_size` rows, each its own short statement, so a large table never holds a
#   long lock or writes one huge transaction.
# - `dry_run` counts what would be deleted and changes nothing.
# - A later phase registers its own snapshot type with Retention.register (for example P2-S12).
module Retention
  Target = Data.define(:model, :time_column, :keep_newest_per_host, :keep_newest)

  DEFAULT_BATCH_SIZE = 1_000

  @targets = []

  class << self
    attr_reader :targets

    # Adds a table to prune. `time_column` is the row's age (received_at, occurred_at); `keep_newest_per_host`
    # needs a host_id column and an index on (host_id, time_column); `keep_newest` keeps the table's newest row.
    def register(model, time_column:, keep_newest_per_host: false, keep_newest: false)
      @targets.reject! { |target| target.model == model }
      @targets << Target.new(model:, time_column:, keep_newest_per_host:, keep_newest:)
    end

    # Deletes (or, in a dry run, counts) the expired rows of every target. Returns { "inventory_snapshots" => 12 }.
    def prune!(now: Time.current, window: Setting.retention_window, dry_run: false, batch_size: DEFAULT_BATCH_SIZE)
      cutoff = now - window
      counts = targets.to_h { |target| [ target.model.table_name, prune_target(target, cutoff:, dry_run:, batch_size:) ] }
      summary = counts.map { |table, count| "#{table}=#{count}" }.join(" ")
      Rails.logger.info("[retention] #{dry_run ? 'dry run, would delete' : 'deleted'} #{summary} older than #{cutoff.utc.iso8601}")
      counts
    end

    private

    def prune_target(target, cutoff:, dry_run:, batch_size:)
      expired = expired_scope(target, cutoff)
      return expired.count if dry_run

      total = 0
      loop do
        deleted = target.model.where(id: expired.limit(batch_size).select(:id)).delete_all
        total += deleted
        break if deleted < batch_size
      end
      total
    end

    def expired_scope(target, cutoff)
      table = target.model.quoted_table_name
      column = target.model.connection.quote_column_name(target.time_column)
      scope = target.model.where("#{table}.#{column} < ?", cutoff)
      if target.keep_newest
        scope = scope.where("EXISTS (SELECT 1 FROM #{table} newer WHERE (newer.#{column}, newer.id) > (#{table}.#{column}, #{table}.id))")
      end
      return scope unless target.keep_newest_per_host

      # Not the newest row of its host: a row with the same host and a later time (or the same time and a
      # higher id) exists. The (host_id, time) index serves the lookup.
      scope.where(<<~SQL.squish)
        EXISTS (SELECT 1 FROM #{table} newer
                WHERE newer.host_id = #{table}.host_id
                  AND (newer.#{column}, newer.id) > (#{table}.#{column}, #{table}.id))
      SQL
    end
  end

  register InventorySnapshot, time_column: :received_at, keep_newest_per_host: true
  register InventoryReportReceipt, time_column: :received_at
  register PackageSnapshot, time_column: :received_at, keep_newest_per_host: true
  register PackageReportReceipt, time_column: :received_at
  register ConfigSnapshot, time_column: :received_at, keep_newest_per_host: true
  register ConfigReportReceipt, time_column: :received_at
  register CisResultChange, time_column: :occurred_at
  register HostStatusEvent, time_column: :occurred_at, keep_newest_per_host: true
  # On-demand report requests (P2-S03), by when they were made: a request ends within an hour, and the audit
  # log keeps who asked.
  register ReportRequest, time_column: :requested_at
  # When each advisory feed refresh started (P2-S15): only the newest matters, for the cool-down, and it is kept
  # however old, since the cool-down has no upper bound (review of #125).
  register AdvisoryRefreshAttempt, time_column: :started_at, keep_newest: true
end
