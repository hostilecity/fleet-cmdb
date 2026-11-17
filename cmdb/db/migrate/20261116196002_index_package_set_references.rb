# The indexes garbage collection needs to tell whether a package set is still referenced (#196, ADR 0028), built
# without blocking package reports.
#
# - host_package_sets: CREATE INDEX CONCURRENTLY.
# - package_snapshots: when it is partitioned (ADR 0027), PostgreSQL refuses CONCURRENTLY on the parent, and a plain
#   CREATE INDEX on the parent holds a SHARE lock on every partition for the whole build. So the index is created on
#   the parent only (ON ONLY: instant, invalid), each partition's is built CONCURRENTLY and attached, and the parent's
#   becomes valid once every partition's is attached; partitions created later get it automatically. When the table
#   is not partitioned yet, it is a plain CREATE INDEX CONCURRENTLY, and a later conversion carries it over.
class IndexPackageSetReferences < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  PARENT = "index_package_snapshots_on_package_set_id".freeze

  def up
    add_index :host_package_sets, :package_set_id, algorithm: :concurrently, if_not_exists: true
    return add_index(:package_snapshots, :package_set_id, name: PARENT, algorithm: :concurrently, if_not_exists: true) unless partitioned?

    execute "CREATE INDEX IF NOT EXISTS #{PARENT} ON ONLY package_snapshots (package_set_id)"
    partitions.each do |partition|
      index = "#{partition}_package_set_id".first(63)
      execute "CREATE INDEX CONCURRENTLY IF NOT EXISTS #{quote_table_name(index)} ON #{quote_table_name(partition)} (package_set_id)"
      execute "ALTER INDEX #{PARENT} ATTACH PARTITION #{quote_table_name(index)}" unless attached?(index)
    end
  end

  def down
    remove_index :package_snapshots, name: PARENT, if_exists: true
    remove_index :host_package_sets, :package_set_id, algorithm: :concurrently, if_exists: true
  end

  private

  def partitioned? = select_value("SELECT relkind FROM pg_class WHERE oid = 'package_snapshots'::regclass") == "p"

  def partitions = select_values("SELECT inhrelid::regclass::text FROM pg_inherits WHERE inhparent = 'package_snapshots'::regclass ORDER BY 1")

  def attached?(index)
    select_value(<<~SQL.squish).present?
      SELECT 1 FROM pg_inherits WHERE inhparent = #{quote(PARENT)}::regclass AND inhrelid = #{quote(index)}::regclass
    SQL
  end
end
