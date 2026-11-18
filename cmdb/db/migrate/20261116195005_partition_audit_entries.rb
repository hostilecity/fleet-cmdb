# ADR 0027, #195: the audit log becomes monthly partitions on occurred_at, with no default partition (it fails closed)
# and never dropped (FR-S.3). No row is copied: the table becomes the partition audit_entries_legacy, kept for ever
# (Partitions::Conversion). Afterwards the PostgreSQL superuser runs ops/postgres/audit-guard.sql once
# (docs/operations/install-server.md, "The audit log's guard").
# Needs DropHistoryForeignKeys first.
class PartitionAuditEntries < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up
    %w[audit_entries].each { |table| Partitions::Conversion.new(table).run! }
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
