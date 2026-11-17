require "rails_helper"

# The online conversion of an existing table into a partitioned one (ADR 0027, "Migration from the current schema"),
# on scratch tables shaped like the real ones. It builds indexes CONCURRENTLY, which cannot run in a transaction, so
# this runs outside the test transaction and drops its tables afterwards.
RSpec.describe Partitions::Conversion do
  self.use_transactional_tests = false

  let(:c) { ApplicationRecord.connection }
  let(:events) { Partitions::Table.new(name: "conv195_events", key: "received_at", width: :day, default: true, append_only: false) }
  let(:snaps) { Partitions::Table.new(name: "conv195_snaps", key: "stored_at", width: :week, default: true, append_only: false) }
  let(:audit) { Partitions::Table.new(name: "conv195_audit", key: "occurred_at", width: :month, default: false, append_only: true) }

  before do
    c.execute(<<~SQL)
      CREATE TABLE conv195_parents (id bigserial PRIMARY KEY);
      INSERT INTO conv195_parents DEFAULT VALUES;
      CREATE TABLE conv195_events (id bigserial PRIMARY KEY, parent_id bigint NOT NULL REFERENCES conv195_parents, report_id uuid NOT NULL,
                                   received_at timestamp(6) NOT NULL, CONSTRAINT conv195_events_report CHECK (report_id IS NOT NULL));
      CREATE UNIQUE INDEX index_conv195_events_on_parent_and_report ON conv195_events (parent_id, report_id);
      CREATE INDEX index_conv195_events_on_received_at ON conv195_events (received_at);
      INSERT INTO conv195_events (parent_id, report_id, received_at)
        SELECT 1, gen_random_uuid(), now() - (g || ' hours')::interval FROM generate_series(1, 500) g;
      CREATE TABLE conv195_snaps (id bigserial PRIMARY KEY, host_id bigint NOT NULL, received_at timestamp(6) NOT NULL);
      CREATE INDEX index_conv195_snaps_on_host_id_and_received_at ON conv195_snaps (host_id, received_at);
      INSERT INTO conv195_snaps (host_id, received_at) SELECT g % 7, now() - (g || ' days')::interval FROM generate_series(1, 200) g;
      CREATE FUNCTION conv195_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'conv195_audit is append-only: %', TG_OP; END $$;
      CREATE TABLE conv195_audit (id bigserial PRIMARY KEY, action text NOT NULL, occurred_at timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP);
      CREATE INDEX index_conv195_audit_on_occurred_at ON conv195_audit (occurred_at);
      CREATE TRIGGER conv195_audit_no_update_or_delete BEFORE UPDATE OR DELETE ON conv195_audit FOR EACH ROW EXECUTE FUNCTION conv195_audit_append_only();
      CREATE TRIGGER conv195_audit_no_truncate BEFORE TRUNCATE ON conv195_audit FOR EACH STATEMENT EXECUTE FUNCTION conv195_audit_append_only();
      INSERT INTO conv195_audit (action, occurred_at) SELECT 'a' || g, now() - (g || ' days')::interval FROM generate_series(1, 100) g;
    SQL
  end

  after do
    c.execute("RESET lock_timeout")
    c.execute("DROP TABLE IF EXISTS conv195_events, conv195_events_new, conv195_snaps, conv195_snaps_new, conv195_audit, conv195_audit_new, conv195_parents CASCADE")
    c.execute("DROP FUNCTION IF EXISTS conv195_audit_append_only()")
  end

  def rows(table) = c.select_rows("SELECT * FROM #{table} ORDER BY id")
  def relkind(table) = c.select_value("SELECT relkind FROM pg_class WHERE relname = #{c.quote(table)}")
  def indexes(table) = c.select_rows("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = #{c.quote(table)} ORDER BY 1").to_h
  def partition_of(table, id) = c.select_value("SELECT tableoid::regclass::text FROM #{table} WHERE id = #{id}")

  it "refuses a table that still has foreign keys, and drops them, out of and into the tables, one at a time" do
    expect { described_class.new(events).run! }.to raise_error(ArgumentError, /conv195_events still has foreign keys/)
    expect(described_class.drop_foreign_keys!(%w[conv195_events])).to eq([ "conv195_events_parent_id_fkey" ])
    expect(described_class.drop_foreign_keys!(%w[conv195_events])).to eq([])
  end

  it "converts a populated table without copying a row: every row, id, and index is there, and new rows go to the new partitions" do
    described_class.drop_foreign_keys!(%w[conv195_events])
    before = rows("conv195_events")
    conversion = described_class.new(events)

    expect(conversion.run!).to eq(:converted)

    expect(relkind("conv195_events")).to eq("p")
    expect(rows("conv195_events")).to eq(before)
    expect(Partitions.list("conv195_events").map(&:name)).to include("conv195_events_legacy", "conv195_events_default",
                                                                     "conv195_events_p#{conversion.cutover.strftime('%Y%m%d')}")
    expect(Partitions.legacy("conv195_events").to).to eq(conversion.cutover)
    expect(conversion.cutover).to be >= 1.day.from_now
    expect(conversion.cutover).to eq(conversion.cutover.beginning_of_day)
    # The parent's indexes keep their names; the unique one without the key is a plain index now.
    expect(indexes("conv195_events")).to eq(
      "conv195_events_pkey" => "CREATE UNIQUE INDEX conv195_events_pkey ON ONLY public.conv195_events USING btree (id, received_at)",
      "index_conv195_events_on_parent_and_report" => "CREATE INDEX index_conv195_events_on_parent_and_report ON ONLY public.conv195_events USING btree (parent_id, report_id)",
      "index_conv195_events_on_received_at" => "CREATE INDEX index_conv195_events_on_received_at ON ONLY public.conv195_events USING btree (received_at)"
    )
    expect(indexes("conv195_events_legacy").values.grep(/UNIQUE INDEX/)).to eq([ "CREATE UNIQUE INDEX conv195_events_legacy_pkey ON public.conv195_events_legacy USING btree (id, received_at)" ])
    expect(c.select_value("SELECT count(*) FROM pg_constraint WHERE conrelid = 'conv195_events_legacy'::regclass AND conname = 'conv195_events_report'")).to eq(1)
    expect(c.select_value("SELECT pg_get_serial_sequence('conv195_events', 'id')")).to eq("public.conv195_events_id_seq")

    id = c.select_value("INSERT INTO conv195_events (parent_id, report_id, received_at) VALUES (1, gen_random_uuid(), #{c.quote(conversion.cutover + 1.hour)}) RETURNING id")
    expect(id).to eq(before.last.first + 1)
    expect(partition_of("conv195_events", id)).to eq("conv195_events_p#{conversion.cutover.strftime('%Y%m%d')}")
    expect(described_class.new(events).run!).to eq(:already)

    # The legacy partition can go whole, and the sequence stays with the parent.
    c.execute("ALTER TABLE conv195_events DETACH PARTITION conv195_events_legacy")
    c.execute("DROP TABLE conv195_events_legacy")
    expect(c.select_value("SELECT pg_get_serial_sequence('conv195_events', 'id')")).to eq("public.conv195_events_id_seq")
  end

  it "adds stored_at to a snapshot table, so old rows sit in the legacy partition and new ones go to the current one at once" do
    before = rows("conv195_snaps")
    conversion = described_class.new(snaps)
    conversion.run!

    expect(conversion.cutover).to eq(Time.current.utc.beginning_of_week(:monday))
    expect(rows("conv195_snaps").map { |r| r.first(3) }).to eq(before)
    expect(c.select_values("SELECT DISTINCT stored_at FROM conv195_snaps")).to eq([ Time.utc(2000, 1, 1) ])
    expect(c.select_value("SELECT count(*) FROM conv195_snaps_legacy")).to eq(200)
    id = c.select_value("INSERT INTO conv195_snaps (host_id, received_at) VALUES (1, now()) RETURNING id")
    expect(partition_of("conv195_snaps", id)).to eq("conv195_snaps_p#{conversion.cutover.strftime('%Y%m%d')}")
  end

  it "keeps an append-only table's guards on every partition, the legacy one included" do
    conversion = described_class.new(audit)
    conversion.run!

    partitions = Partitions.list("conv195_audit")
    expect(partitions.none?(&:default?)).to be(true)
    expect(partitions.first).to have_attributes(name: "conv195_audit_legacy", to: conversion.cutover)
    partitions.each do |p|
      expect(c.select_values("SELECT tgname FROM pg_trigger WHERE tgrelid = #{c.quote(p.name)}::regclass ORDER BY 1"))
        .to eq(%w[conv195_audit_no_update_or_delete conv195_audit_partition_no_truncate]), p.name
    end
    expect(c.select_values("SELECT tgname FROM pg_trigger WHERE tgrelid = 'conv195_audit'::regclass ORDER BY 1")).to eq(%w[conv195_audit_no_truncate conv195_audit_no_update_or_delete])
    [ "UPDATE conv195_audit SET action = 'x'", "DELETE FROM conv195_audit_legacy", "TRUNCATE conv195_audit_legacy", "TRUNCATE conv195_audit" ].each do |sql|
      expect { c.execute(sql) }.to raise_error(ActiveRecord::StatementInvalid, /append-only/), sql
    end
    expect(c.select_value("SELECT count(*) FROM conv195_audit")).to eq(100)
  end

  it "can run again after it failed part-way, rebuilding an index left invalid" do
    described_class.drop_foreign_keys!(%w[conv195_events])
    failed = described_class.new(events, tries: 1)
    allow(failed).to receive(:swap).and_raise(Partitions::Busy, "lock not granted in 1 tries of 500ms")
    expect { failed.run! }.to raise_error(Partitions::Busy)
    expect(relkind("conv195_events")).to eq("r")
    expect(c.select_value("SELECT count(*) FROM conv195_events")).to eq(500)
    c.execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'conv195_events_legacy_pkey'::regclass") # as an interrupted build leaves it

    expect(described_class.new(events).run!).to eq(:converted)
    expect(c.select_value("SELECT count(*) FROM conv195_events_legacy")).to eq(500)
  end

  it "stops before the swap when the cutover it chose has passed" do
    c.execute("DELETE FROM conv195_events WHERE received_at > now() - interval '10 days'")
    described_class.drop_foreign_keys!(%w[conv195_events])
    expect { described_class.new(events, now: 5.days.ago).run! }.to raise_error(RuntimeError, /the cutover .* has passed: run the conversion of conv195_events again/)
    expect(relkind("conv195_events")).to eq("r")
  end
end
