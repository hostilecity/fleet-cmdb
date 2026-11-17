# ADR 0027, #195: snapshots and status events become weekly partitions on a new stored_at ("when this row was last
# stored"); retention moves each host's newest row forward before dropping its partition. No row is copied: each table
# becomes the partition <table>_legacy and ages out after one retention window (Partitions::Conversion).
# Needs DropHistoryForeignKeys first.
class PartitionSnapshotsAndStatusEvents < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up
    %w[inventory_snapshots config_snapshots package_snapshots host_status_events].each { |table| Partitions::Conversion.new(table).run! }
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
