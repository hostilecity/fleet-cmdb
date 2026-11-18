# ADR 0027, #195, step 0: the history tables lose their foreign keys, out (to hosts and the CIS tables) and in (from
# cis_results and cis_result_changes to config_snapshots). With them, creating, detaching, and dropping a partition
# would lock hosts. Each key is one short statement under a lock timeout; this is the only step that locks hosts.
class DropHistoryForeignKeys < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up
    Partitions::Conversion.drop_foreign_keys!(Partitions::TABLES.keys)
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
