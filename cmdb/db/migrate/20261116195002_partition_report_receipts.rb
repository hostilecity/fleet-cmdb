# ADR 0027, #195: the report receipts become daily partitions on received_at. A unique (host_id, report_id) cannot
# span partitions, so duplicate reports are found under the host lock instead (ReportReceipts). No row is copied: each
# table becomes the partition <table>_legacy and ages out with the receipt window (Partitions::Conversion).
# Needs DropHistoryForeignKeys first.
class PartitionReportReceipts < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up
    %w[inventory_report_receipts config_report_receipts package_report_receipts].each { |table| Partitions::Conversion.new(table).run! }
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
