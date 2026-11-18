# The indexes garbage collection needs to tell whether a package set is still referenced (#196, ADR 0028), built
# without blocking package reports.
#
# - host_package_sets and host_vulnerability_evaluations: CREATE INDEX CONCURRENTLY.
# - package_snapshots: when it is partitioned (ADR 0027), PostgreSQL refuses CONCURRENTLY on the parent, and a plain
#   CREATE INDEX on the parent holds a SHARE lock on every partition for the whole build. So the index is created on
#   the parent only (ON ONLY: instant, invalid), each partition's is built CONCURRENTLY and attached, and the parent's
#   becomes valid once every partition's is attached; partitions created later get it automatically. When the table
#   is not partitioned yet, it is a plain CREATE INDEX CONCURRENTLY, and a later conversion carries it over.
# - A CONCURRENTLY build that failed leaves an INVALID index, which IF NOT EXISTS would keep and the planner never
#   uses (garbage collection would then scan every snapshot per set). So an invalid one is dropped and built again.
class IndexPackageSetReferences < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  PARENT = "index_package_snapshots_on_package_set_id".freeze

  def up
    drop_invalid("index_host_package_sets_on_package_set_id")
    drop_invalid("index_host_vulnerability_evaluations_on_package_set_id")
    drop_invalid(PARENT)
    add_index :host_package_sets, :package_set_id, algorithm: :concurrently, if_not_exists: true
    add_index :host_vulnerability_evaluations, :package_set_id, algorithm: :concurrently, if_not_exists: true
    return add_index(:package_snapshots, :package_set_id, name: PARENT, algorithm: :concurrently, if_not_exists: true) unless partitioned?

    execute "CREATE INDEX IF NOT EXISTS #{PARENT} ON ONLY package_snapshots (package_set_id)"
    partitions.each do |partition|
      index = "#{partition}_package_set_id".first(63)
      drop_invalid(index)
      execute "CREATE INDEX CONCURRENTLY IF NOT EXISTS #{quote_table_name(index)} ON #{quote_table_name(partition)} (package_set_id)"
      execute "ALTER INDEX #{PARENT} ATTACH PARTITION #{quote_table_name(index)}" unless attached?(index)
    end
  end

  def down
    remove_index :package_snapshots, name: PARENT, if_exists: true
    remove_index :host_package_sets, :package_set_id, algorithm: :concurrently, if_exists: true
    remove_index :host_vulnerability_evaluations, :package_set_id, algorithm: :concurrently, if_exists: true
  end

  private

  # Drops index if it exists and is INVALID (a failed CONCURRENTLY build). The parent's ON ONLY index is invalid until
  # every partition's is attached, so it is dropped only when nothing is attached to it yet.
  def drop_invalid(index)
    kind = select_value(<<~SQL.squish)
      SELECT c.relkind FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
      WHERE c.relname = #{quote(index)} AND NOT i.indisvalid
        AND NOT EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent = c.oid)
    SQL
    # A partitioned index cannot be dropped CONCURRENTLY; with nothing attached it is only a catalog row.
    execute "DROP INDEX #{'CONCURRENTLY ' unless kind == 'I'}IF EXISTS #{quote_table_name(index)}" if kind
  end

  def partitioned? = select_value("SELECT relkind FROM pg_class WHERE oid = 'package_snapshots'::regclass") == "p"

  def partitions = select_values("SELECT inhrelid::regclass::text FROM pg_inherits WHERE inhparent = 'package_snapshots'::regclass ORDER BY 1")

  def attached?(index)
    select_value(<<~SQL.squish).present?
      SELECT 1 FROM pg_inherits WHERE inhparent = #{quote(PARENT)}::regclass AND inhrelid = #{quote(index)}::regclass
    SQL
  end
end
