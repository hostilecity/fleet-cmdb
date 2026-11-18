# ADR 0027, #195: CIS result changes become weekly partitions on occurred_at. No row is copied: the table becomes the
# partition cis_result_changes_legacy and ages out after one retention window (Partitions::Conversion).
# Needs DropHistoryForeignKeys first.
class PartitionCisResultChanges < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up
    %w[cis_result_changes].each { |table| Partitions::Conversion.new(table).run! }
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
