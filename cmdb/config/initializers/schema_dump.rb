# db/schema.rb and time-partitioned tables (ADR 0027, "db/schema.rb stays"). Rails dumps a partitioned parent correctly
# (options: "PARTITION BY RANGE (...)" and its composite primary key) but would dump each partition as a table of its
# own, and fx would dump the triggers PostgreSQL clones to every partition, and the audit partitions' own truncate
# guards. So partitions are left out of the dump, and so are triggers on a partition: `partitions:ensure` (run after
# db:schema:load and db:prepare) creates the partitions and their guards.
# The tables are Partitions::TABLES (not autoloaded here, during initialization); spec/db/schema_dump_spec.rb checks
# the two lists match.
ActiveSupport.on_load(:active_record) do
  tables = %w[inventory_report_receipts config_report_receipts package_report_receipts inventory_snapshots config_snapshots
              package_snapshots host_status_events cis_result_changes vulnerability_work_events audit_entries]
  ActiveRecord::SchemaDumper.ignore_tables |= [ /\A(?:#{tables.join('|')})_(?:p\d{8}|default|legacy|new)\z/ ]
end

require "fx/adapters/postgres/triggers"
Fx::Adapters::Postgres::Triggers.send(:remove_const, :TRIGGERS_WITH_DEFINITIONS_QUERY)
Fx::Adapters::Postgres::Triggers.const_set(:TRIGGERS_WITH_DEFINITIONS_QUERY, <<~SQL.freeze)
  SELECT
      pt.tgname AS name,
      pg_get_triggerdef(pt.oid) AS definition
  FROM pg_trigger pt
  JOIN pg_class pc
      ON (pc.oid = pt.tgrelid)
  JOIN pg_proc pp
      ON (pp.oid = pt.tgfoid)
  JOIN pg_namespace pn
      ON pn.oid = pc.relnamespace
  WHERE pn.nspname = ANY (current_schemas(false))
      AND pt.tgname NOT ILIKE '%constraint%'
      AND pt.tgname NOT ILIKE 'pg%'
      AND NOT pc.relispartition
  ORDER BY pc.oid;
SQL
