require "rails_helper"

# db/schema.rb and the partitioned history tables (ADR 0027, "db/schema.rb stays"): the dump holds each partitioned
# parent and none of its partitions, nor the triggers on them, and matches db/schema.rb for those tables. The two
# tooling patches (config/initializers/schema_dump.rb) are what keep this true across Rails and fx upgrades.
RSpec.describe "db/schema.rb with partitioned tables" do
  let(:dump) do
    stream = StringIO.new
    ActiveRecord::SchemaDumper.dump(ApplicationRecord.connection_pool, stream)
    stream.string
  end
  let(:schema) { Rails.root.join("db/schema.rb").read }

  # A table's create_table line and its column and index lines, without check constraints and partial indexes, whose
  # text differs between PostgreSQL versions.
  def block(text, table)
    text[/^  create_table "#{table}".*?^  end$/m].lines.reject { |line| line.include?("t.check_constraint") || line.include?("where:") }.join
  end

  it "lists the same tables in the dumper's ignore list as Partitions::TABLES" do
    Partitions::TABLES.each_key do |table|
      %w[p20261116 default legacy new].each do |suffix|
        expect(ActiveRecord::SchemaDumper.ignore_tables.any? { |pattern| pattern.match?("#{table}_#{suffix}") }).to be(true), "#{table}_#{suffix}"
      end
    end
    expect(ActiveRecord::SchemaDumper.ignore_tables.any? { |pattern| pattern.match?("hosts_default") }).to be(false)
  end

  it "dumps each partitioned parent as in db/schema.rb, and no partition or trigger on one" do
    Partitions::TABLES.each_value do |table|
      expect(dump).to include(%(create_table "#{table.name}", primary_key: ["id", "#{table.key}"], options: "PARTITION BY RANGE (#{table.key})"))
      expect(block(dump, table.name)).to eq(block(schema, table.name)), table.name
    end
    expect(dump).not_to match(/create_table "\w+_(p\d{8}|default|legacy)"/)
    expect(dump.scan(/create_trigger :audit_entries_no_update_or_delete/).size).to eq(1)
    expect(dump).not_to include("audit_entries_partition_no_truncate")
    expect(dump).not_to include("fleet_audit_guard")
  end
end
