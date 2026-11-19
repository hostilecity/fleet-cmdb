require "rails_helper"

# The history tables' time partitions (ADR 0027, #195). The test database has the partitions spec/rails_helper.rb
# creates; examples that add or drop partitions do it inside their transaction, so it is rolled back.
RSpec.describe Partitions do
  let(:c) { ApplicationRecord.connection }
  let(:receipts) { "inventory_report_receipts" }
  let(:host) { create(:host) }

  # A second session, as another process would hold one.
  def other_session(**options)
    session = PG.connect(dbname: c.current_database, **options)
    yield session
  ensure
    session&.close
  end

  def receipt(at, host_id: host.id)
    InventoryReportReceipt.insert!({ host_id:, report_id: SecureRandom.uuid, received_at: at })
  end

  def names(table) = described_class.list(table).map(&:name)

  def triggers(relname)
    c.select_values("SELECT tgname FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid WHERE r.relname = #{c.quote(relname)} ORDER BY 1")
  end

  describe ".ensure!" do
    it "has created every table's partitions ahead and a default, and creates nothing more when run again" do
      expect(described_class.ensure!.values).to all(be_empty)
      described_class::TABLES.each_value do |table|
        parts = described_class.list(table.name)
        expect(parts.count { |p| p.from && p.from > Time.current }).to be >= described_class::AHEAD, table.name
        expect(parts.any?(&:default?)).to eq(table.default), table.name
      end
    end

    it "creates the partitions a later time needs, one width each, in one contiguous chain" do
      last = described_class.list(receipts).reject(&:default?).last
      created = described_class.ensure!(now: last.to + 1.day, tables: [ receipts ])
      expect(created[receipts]).to eq([ "#{receipts}_p#{last.to.strftime('%Y%m%d')}", "#{receipts}_p#{(last.to + 1.day).strftime('%Y%m%d')}",
                                        "#{receipts}_p#{(last.to + 2.days).strftime('%Y%m%d')}", "#{receipts}_p#{(last.to + 3.days).strftime('%Y%m%d')}",
                                        "#{receipts}_p#{(last.to + 4.days).strftime('%Y%m%d')}" ])
      ranged = described_class.list(receipts).reject(&:default?)
      expect(ranged.each_cons(2).map { |a, b| a.to == b.from }).to all(be(true))
      expect(ranged.map { |p| p.to - p.from }.uniq).to eq([ 1.day ])
    end

    it "creates partitions back to a time, and moves rows the default partition holds into them" do
      first = described_class.list(receipts).reject(&:default?).first
      old = receipt(first.from - 2.days + 1.hour)
      expect(c.select_value("SELECT count(*) FROM #{receipts}_default")).to eq(1)

      created = described_class.ensure!(tables: [ receipts ]) # the default's oldest row is reason enough
      expect(created[receipts]).to eq([ "#{receipts}_p#{(first.from - 1.day).strftime('%Y%m%d')}", "#{receipts}_p#{(first.from - 2.days).strftime('%Y%m%d')}" ])
      expect(c.select_value("SELECT count(*) FROM #{receipts}_default")).to eq(0)
      expect(c.select_value("SELECT tableoid::regclass::text FROM #{receipts} WHERE id = #{old.rows.first.first}")).to eq("#{receipts}_p#{(first.from - 2.days).strftime('%Y%m%d')}")

      described_class.ensure!(from: first.from - 4.days, tables: [ receipts ])
      expect(described_class.list(receipts).reject(&:default?).first.from).to eq(first.from - 4.days)
    end

    it "moves rows the default holds ahead of the chain when it creates their partition" do
      last = described_class.list(receipts).reject(&:default?).last
      ahead = receipt(last.to + 2.hours)
      described_class.ensure!(now: last.to, tables: [ receipts ])
      expect(c.select_value("SELECT tableoid::regclass::text FROM #{receipts} WHERE id = #{ahead.rows.first.first}")).to eq("#{receipts}_p#{last.to.strftime('%Y%m%d')}")
    end

    it "uses 30-day partitions for the weekly tables when the window is over 180 days, from the next one created" do
      Setting.update_retention_days!(365, actor: Audit::SYSTEM)
      last = described_class.list("cis_result_changes").reject(&:default?).last
      described_class.ensure!(now: last.to, tables: [ "cis_result_changes" ])
      added = described_class.list("cis_result_changes").reject(&:default?).select { |p| p.from >= last.to }
      expect(added.map { |p| p.to - p.from }.uniq).to eq([ 30.days ])
      expect(added.first.from).to eq(last.to)
    end

    it "aligns daily, weekly, and monthly partitions" do
      at = Time.utc(2026, 11, 18, 15, 30)
      expect(described_class.align(described_class.table(receipts), at)).to eq(Time.utc(2026, 11, 18))
      expect(described_class.align(described_class.table("host_status_events"), at)).to eq(Time.utc(2026, 11, 16))
      expect(described_class.align(described_class.table("audit_entries"), at)).to eq(Time.utc(2026, 11, 1))
    end

    it "leaves a table whose lock it cannot get for the next run, and says so" do
      last = described_class.list(receipts).reject(&:default?).last
      allow(Rails.logger).to receive(:warn)
      other_session do |session|
        session.exec("BEGIN")
        session.exec("LOCK TABLE #{receipts} IN ACCESS SHARE MODE")
        expect(described_class.ensure!(now: last.to + 1.day, tables: [ receipts ])).to eq(receipts => [])
        session.exec("ROLLBACK")
      end
      expect(Rails.logger).to have_received(:warn).with(/#{receipts}: lock not granted in 3 tries of 150ms; the next run tries again/)
      expect(described_class.list(receipts).reject(&:default?).last).to eq(last)
    end

    it "creates a missing default partition" do
      c.execute("DROP TABLE #{receipts}_default")
      expect(described_class.ensure!(tables: [ receipts ])).to eq(receipts => [ "#{receipts}_default" ])
      expect(described_class.list(receipts).last).to be_default
    end

    it "skips a table that is not partitioned" do
      allow(described_class).to receive(:partitioned?).and_return(false)
      expect(described_class.ensure!.values).to all(eq([]))
    end
  end

  describe "the audit log" do
    let(:audit_partitions) { described_class.list(described_class::AUDIT) }

    it "has no default partition, so a write outside every partition fails rather than going unrecorded" do
      expect(audit_partitions.none?(&:default?)).to be(true)
      after = audit_partitions.last.to + 1.day
      expect do
        AuditEntry.transaction(requires_new: true) do
          AuditEntry.insert_all!([ { actor_type: "system", action: Audit::Actions::HOST_EDITED, changeset: {}, occurred_at: after } ])
        end
      end.to raise_error(ActiveRecord::StatementInvalid, /no partition of relation "audit_entries" found for row/)
    end

    it "gives every partition, and every new one, its own truncate guard, and refuses truncating one" do
      described_class.ensure!(now: audit_partitions.last.from, tables: [ described_class::AUDIT ])
      parts = described_class.list(described_class::AUDIT)
      expect(parts.size).to be > audit_partitions.size
      parts.each { |p| expect(triggers(p.name)).to include("audit_entries_partition_no_truncate", "audit_entries_no_update_or_delete"), p.name }
      expect do
        AuditEntry.transaction(requires_new: true) { c.execute("TRUNCATE #{parts.last.name}") }
      end.to raise_error(ActiveRecord::StatementInvalid, /append-only: TRUNCATE/)
    end

    it "refuses updates and deletes through a partition too" do
      create(:host) # writes an entry
      partition = c.select_value("SELECT tableoid::regclass::text FROM audit_entries ORDER BY id DESC LIMIT 1")
      [ "UPDATE #{partition} SET action = 'host.retired'", "DELETE FROM #{partition}", "UPDATE audit_entries SET occurred_at = occurred_at - interval '400 days'" ].each do |sql|
        expect { AuditEntry.transaction(requires_new: true) { c.execute(sql) } }.to raise_error(ActiveRecord::StatementInvalid, /append-only/), sql
      end
    end

    it "is never detached or dropped by this code" do
      expect { described_class.detach_and_drop!(described_class::AUDIT, audit_partitions.first) }.to raise_error(ArgumentError, /never detached or dropped/)
      expect { described_class.drop_leftovers!(described_class::AUDIT) }.to raise_error(ArgumentError, /never detached or dropped/)
      expect(Retention.targets.map { |t| t.model.table_name }).not_to include(described_class::AUDIT)
      expect(Retention.cutoff_for(described_class::AUDIT)).to be_nil
    end
  end

  describe ".detach_and_drop! and .drop_leftovers!" do
    it "checks the maintenance lock before each drop, and drops nothing once it is lost (#198)" do
      first, second = described_class.list(receipts).reject(&:default?).first(2)
      lost = -> { raise SessionLock::Lost, "gone" }
      expect { described_class.detach_and_drop!(receipts, first, still_held: lost) }.to raise_error(SessionLock::Lost)
      expect(names(receipts)).to include(first.name)
      c.execute("ALTER TABLE #{receipts} DETACH PARTITION #{second.name}")
      c.execute("ALTER TABLE #{second.name} RENAME TO #{second.name}_retired")
      expect { described_class.drop_leftovers!(receipts, still_held: lost) }.to raise_error(SessionLock::Lost)
      expect(c.table_exists?("#{second.name}_retired")).to be(true)
    end

    it "detaches and drops a partition, and drops one an earlier run detached but did not drop" do
      first, second = described_class.list(receipts).reject(&:default?).first(2)
      described_class.detach_and_drop!(receipts, first)
      expect(names(receipts)).not_to include(first.name)
      expect(c.table_exists?(first.name)).to be(false)

      # One this code detached (renamed _retired) is dropped; one an operator detached keeps its name and stays.
      third = described_class.list(receipts).reject(&:default?).second
      c.execute("ALTER TABLE #{receipts} DETACH PARTITION #{second.name}")
      c.execute("ALTER TABLE #{second.name} RENAME TO #{second.name}_retired")
      c.execute("ALTER TABLE #{receipts} DETACH PARTITION #{third.name}")
      expect(described_class.drop_leftovers!(receipts)).to eq([ "#{second.name}_retired" ])
      expect(c.table_exists?("#{second.name}_retired")).to be(false)
      expect(c.table_exists?(third.name)).to be(true)
    end
  end

  describe ".backup_running? and .maintain!" do
    it "gives Retention.retire! the maintenance lock's check (#198)" do
      checks = []
      allow(Retention).to receive(:retire!) { |still_held:, **| checks << still_held && {} }
      described_class.maintain!
      expect(checks.size).to eq(1)
      expect(checks.first).to respond_to(:call)
    end

    it "does no partition work while pg_dump is dumping this database" do
      allow(Retention).to receive(:retire!)
      other_session(application_name: "pg_dump") do
        expect(described_class.backup_running?).to be(true)
        expect(described_class.maintain!).to eq("skipped" => "backup running")
      end
      expect(Retention).not_to have_received(:retire!)
      20.times { described_class.backup_running? ? sleep(0.1) : break } # the closed session may linger briefly
      expect(described_class.backup_running?).to be(false)
    end

    it "creates partitions ahead, then retires what has expired; a dry run creates nothing" do
      allow(Retention).to receive(:retire!).and_return({})
      allow(described_class).to receive(:ensure!).and_call_original
      expect(described_class.maintain!).to eq("created" => described_class::TABLES.keys.index_with { [] }, "retired" => {})
      expect(described_class.maintain!(dry_run: true)).to eq("created" => {}, "retired" => {})
      expect(described_class).to have_received(:ensure!).once
      expect(Retention).to have_received(:retire!).with(now: anything, dry_run: true, still_held: anything)
    end
  end

  describe ".health" do
    it "is ok with the partitions the maintenance keeps" do
      expect(described_class.health).to eq(:ok)
      expect(described_class.problems).to be_empty
    end

    it "warns about rows in a default partition, partitions due for retirement, and too few ahead" do
      receipt(1.year.from_now)
      expect(described_class.health).to eq(:warning)
      expect(described_class.problems.map(&:text)).to include("#{described_class.label(receipts)}: the default partition has rows (the next maintenance run moves them)")

      described_class.ensure!(from: 12.days.ago, tables: [ receipts ])
      expect(described_class.problems.map(&:text)).to include("#{described_class.label(receipts)}: a partition has been due for retirement for 3 days")

      later = described_class.problems(now: 10.days.from_now).map(&:text)
      expect(later).to include("#{described_class.label(receipts)}: 0 partitions created ahead, fewer than 2", "#{described_class.label(receipts)}: a partition ahead has been missing for 3 days")
    end

    it "fails when the audit log has fewer than two months ahead, since its writes would fail" do
      expect(described_class.health(now: 3.months.from_now)).to eq(:failing)
      expect(described_class.problems(now: 3.months.from_now)).to include(
        described_class::Problem.new(severity: :failing, text: "The audit log (audit_entries): 0 partitions created ahead, fewer than 2")
      )
    end
  end

  describe ".audit_guard_installed?" do
    it "is false until the superuser has run ops/postgres/audit-guard.sql" do
      expect(described_class.audit_guard_installed?).to be(false)
    end
  end

  describe ".orphans" do
    it "reports recent rows whose host or rule does not exist" do
      receipt(Time.current, host_id: 2_000_000_000)
      receipt(Time.current)
      define_cis_rules(cis_rule_hash)
      rule = CisRule.first
      CisResultChange.insert_all!([ { host_id: host.id, cis_rule_id: 2_000_000_000, to_result: "pass", occurred_at: 1.year.ago },
                                    { host_id: host.id, cis_rule_id: rule.id, to_result: "pass", occurred_at: Time.current } ])
      expect(described_class.orphans).to eq("inventory_report_receipts.host_id" => 1, "cis_result_changes.cis_rule_id" => 1)
    end

    it "checks only tables that are partitioned" do
      allow(described_class).to receive(:partitioned?).and_return(false)
      receipt(Time.current, host_id: 2_000_000_000)
      expect(described_class.orphans).to eq({})
    end
  end
  describe "moving rows out of a default partition (review of #239)" do
    let(:first) { described_class.list(receipts).reject(&:default?).first }

    it "sets the default aside, puts an empty one in its place, and moves its rows back in batches, each its own statement" do
      stub_const("Partitions::MOVE_BATCH", 2)
      ids = Array.new(5) { |i| receipt(first.from - 2.days + i.minutes).rows.first.first }
      ahead = receipt(2.years.from_now).rows.first.first
      inserts = []
      counter = ->(*, payload) { inserts << payload[:sql] if payload[:sql].start_with?("WITH batch AS (DELETE FROM") }

      ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { described_class.ensure!(tables: [ receipts ]) }

      expect(inserts.size).to eq(4) # 2 + 2 + 2 (the row far ahead too, which goes back to the new default), then none left
      expect(c.table_exists?("#{receipts}_default_moving")).to be(false)
      expect(ids.map { |id| c.select_value("SELECT tableoid::regclass::text FROM #{receipts} WHERE id = #{id}") }.uniq)
        .to eq([ "#{receipts}_p#{(first.from - 2.days).strftime('%Y%m%d')}" ])
      expect(c.select_value("SELECT tableoid::regclass::text FROM #{receipts} WHERE id = #{ahead}")).to eq("#{receipts}_default")
    end

    # A run whose maintenance lock is lost part-way through moving rows back stops before its next batch, so a second
    # run that takes the lock never works on the same moving table beside it, and the table is not dropped (#198).
    it "checks the maintenance lock before each batch it moves back, and stops with the rest set aside once it is lost" do
      stub_const("Partitions::MOVE_BATCH", 2)
      Array.new(5) { |i| receipt(first.from - 2.days + i.minutes) }
      batches = 0
      counter = ->(*, payload) { batches += 1 if payload[:sql].start_with?("WITH batch AS (DELETE FROM") }
      allow(SessionLock).to receive(:hold).and_wrap_original do |original, key, &block|
        original.call(key) { block.call(-> { raise SessionLock::Lost, "gone" if batches == 1 }) }
      end

      expect { ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { described_class.ensure!(tables: [ receipts ]) } }
        .to raise_error(SessionLock::Lost)
      expect(batches).to eq(1)
      expect(c.table_exists?("#{receipts}_default_moving")).to be(true) # not dropped: 3 rows are still in it
      expect(c.select_value("SELECT count(*) FROM #{receipts}_default_moving")).to eq(3)
    end

    it "leaves rows far ahead in the default without setting it aside" do
      receipt(2.years.from_now)
      expect(described_class.ensure!(tables: [ receipts ])).to eq(receipts => [])
      expect(c.table_exists?("#{receipts}_default_moving")).to be(false)
    end

    it "never drops a set-aside table that still has rows, when a batch moved fewer than a whole batch (review of #237)" do
      stub_const("Partitions::MOVE_BATCH", 1_000)
      3.times { |i| receipt(first.from - 2.days + i.minutes) }
      allow(c).to receive(:exec_update).and_call_original
      allow(c).to receive(:exec_update).with(a_string_starting_with("WITH batch AS")).and_return(0) # as if another run had moved them
      allow(Rails.logger).to receive(:warn)

      described_class.ensure!(tables: [ receipts ])

      expect(c.select_value("SELECT count(*) FROM #{receipts}_default_moving")).to eq(3)
      expect(Rails.logger).to have_received(:warn).with("[partitions] #{receipts}: rows are still set aside in #{receipts}_default_moving; left for the next run")
      expect(described_class.problems.map(&:text)).to include("#{described_class.label(receipts)}: rows set aside from the default partition are still being moved back")
    end

    it "picks up rows set aside by a run that stopped part-way, and says so until they are back" do
      c.execute("CREATE TABLE #{receipts}_default_moving (LIKE #{receipts})")
      c.execute("INSERT INTO #{receipts}_default_moving (id, host_id, report_id, received_at) VALUES (nextval('#{receipts}_id_seq'), #{host.id}, gen_random_uuid(), #{c.quote(first.from - 1.day)})")
      expect(described_class.problems.map(&:text)).to include("#{described_class.label(receipts)}: rows set aside from the default partition are still being moved back")

      described_class.ensure!(tables: [ receipts ])

      expect(c.table_exists?("#{receipts}_default_moving")).to be(false)
      expect(c.select_value("SELECT count(*) FROM #{receipts}_p#{(first.from - 1.day).strftime('%Y%m%d')}")).to eq(1)
    end
  end

  describe "one maintenance run at a time (review of #239)" do
    # Behind a transaction-mode pooler the maintenance lock is on the direct connection (#198), uncached, and checked
    # before each table, so a run whose lock session ended stops before its next table's DDL.
    it "holds the lock on the direct connection, and stops before the next table once it is lost" do
      use_direct_database
      work = ApplicationRecord.connection.select_value("SELECT pg_backend_pid()")
      holders = nil
      tables = 0
      allow(described_class).to receive(:partitioned?).and_wrap_original do |original, name|
        tables += 1
        if tables == 1
          session = separate_session
          holders = session.select_values(<<~SQL.squish)
            SELECT l.pid FROM pg_locks l JOIN pg_database d ON d.oid = l.database
             WHERE l.locktype = 'advisory' AND l.granted AND d.datname = current_database() AND l.classid = 0 AND l.objid = #{described_class::LOCK_KEY}
          SQL
          session.disconnect!
        end
        expect(end_lock_holder(0, described_class::LOCK_KEY)).to eq(1) if tables == 2
        original.call(name)
      end

      expect { Rails.application.executor.wrap { described_class.ensure! } }.to raise_error(SessionLock::Lost)
      expect(holders.size).to eq(1)
      expect(holders).not_to include(work)
      expect(tables).to eq(2) # no table after the lock was lost
    end

    it "does nothing, and says so, while another session holds the maintenance lock" do
      allow(Rails.logger).to receive(:info)
      allow(Retention).to receive(:retire!)
      other_session do |session|
        session.exec("SELECT pg_advisory_lock(#{described_class::LOCK_KEY})")
        expect(described_class.maintain!).to eq("skipped" => "another maintenance run is in progress")
        expect(described_class.ensure!).to be_nil
        session.exec("SELECT pg_advisory_unlock(#{described_class::LOCK_KEY})")
      end
      expect(Retention).not_to have_received(:retire!)
      expect(Rails.logger).to have_received(:info).with("[partitions] another maintenance run is in progress: nothing done")
      expect(described_class.ensure!).to eq(described_class::TABLES.keys.index_with { [] })
    end
  end

  describe ".attention and .report_changes (review of #239)" do
    let(:cache) { ActiveSupport::Cache::MemoryStore.new }

    before { allow(Rails).to receive(:cache).and_return(cache) }

    it "logs a problem once when it appears and once when it clears, not on every request" do
      allow(Rails.logger).to receive(:warn)
      allow(Rails.logger).to receive(:info)
      problem = described_class::Problem.new(severity: :warning, text: "inventory_report_receipts: the default partition has rows")
      2.times { described_class.report_changes([ problem ]) }
      described_class.report_changes([])
      expect(Rails.logger).to have_received(:warn).with("[partitions] needs attention: #{problem.text}").once
      expect(Rails.logger).to have_received(:info).with("[partitions] resolved: #{problem.text}").once
    end

    it "has the maintenance run report its problems, and lists them, and the nightly check's orphans, for the banner" do
      receipt(1.year.from_now)
      allow(Rails.logger).to receive(:warn)
      described_class.maintain!
      expect(Rails.logger).to have_received(:warn).with("[partitions] needs attention: #{described_class.label(receipts)}: the default partition has rows (the next maintenance run moves them)")

      cache.write(described_class::ORPHANS_KEY, { "inventory_report_receipts.host_id" => 2 })
      expect(described_class.attention.map(&:text)).to eq([ "#{described_class.label(receipts)}: the default partition has rows (the next maintenance run moves them)",
                                                "inventory_report_receipts.host_id: 2 recent rows name a host or rule that does not exist (bin/rails partitions:check)" ])
      expect(described_class.health).to eq(:warning)
    end

    it "adds an audit guard that does not hold, in production" do
      allow(Rails.env).to receive(:production?).and_return(true)
      described_class.maintain!
      expect(described_class.attention.map(&:text)).to match([ /\AThe audit log's guard does not hold: the app's PostgreSQL role is (the bootstrap superuser \(OID 10, a container created with POSTGRES_USER=cmdb\), which cannot be demoted|a superuser, so no guard can hold against it): the cluster must be rebuilt \(install-server.md, \"If cmdb is or was a superuser\"\)\.\z/ ])
    end
  end
  describe "while a default partition's rows are set aside (review 2 of #239)" do
    let(:first) { described_class.list(receipts).reject(&:default?).first }

    def set_aside(table, rows_sql)
      c.execute("CREATE TABLE #{table}_default_moving (LIKE #{table} INCLUDING ALL)")
      c.execute("INSERT INTO #{table}_default_moving #{rows_sql}")
    end

    it "checks a report for a duplicate in one query while nothing is set aside (review 3 of #239, N6)" do
      ReportReceipts.record!(InventoryReportReceipt, host_id: host.id, report_id: SecureRandom.uuid, now: Time.current)
      statements = []
      counter = ->(*, payload) { statements << payload[:sql] unless payload[:name] == "SCHEMA" || payload[:sql].match?(/SAVEPOINT|BEGIN|COMMIT/) }
      ActiveSupport::Notifications.subscribed(counter, "sql.active_record") do
        expect(ReportReceipts.record!(InventoryReportReceipt, host_id: host.id, report_id: SecureRandom.uuid, now: Time.current)).to be(true)
      end
      expect(statements.size).to eq(2) # the lookup with the set-aside check, and the insert
    end

    it "still recognises a retried report whose receipt is set aside" do
      report_id = SecureRandom.uuid
      set_aside(receipts, "(id, host_id, report_id, received_at) VALUES (nextval('#{receipts}_id_seq'), #{host.id}, #{c.quote(report_id)}, #{c.quote(first.from - 1.day)})")
      expect(ReportReceipts.record!(InventoryReportReceipt, host_id: host.id, report_id:, now: Time.current)).to be(false)
      expect(ReportReceipts.record!(InventoryReportReceipt, host_id: host.id, report_id: SecureRandom.uuid, now: Time.current)).to be(true)
    end

    it "lets CIS evaluation read a host's latest config snapshot even when it is set aside" do
      older = ConfigSnapshot.create!(host:, facts: {}, content_hash: "a" * 64, manifest_version: 1, report_id: SecureRandom.uuid,
                                     collected_at: 2.days.ago, received_at: 2.days.ago)
      newest_id = c.select_value("SELECT nextval('config_snapshots_id_seq')")
      set_aside("config_snapshots", "(id, host_id, facts, content_hash, manifest_version, report_id, collected_at, received_at, stored_at) " \
                                   "VALUES (#{newest_id}, #{host.id}, '{}', '#{'b' * 64}', 1, gen_random_uuid(), now(), now(), now())")
      expect(ConfigSnapshot.where(host:).pluck(:id)).to eq([ older.id ]) # what a plain reader sees in the window
      expect(CisEvaluation.send(:latest_snapshot_ids, [ host.id ])).to eq(host.id => newest_id)
    end

    it "moves the newest rows back first" do
      stub_const("Partitions::MOVE_BATCH", 1)
      ids = [ 3, 2, 1 ].map { |days| receipt(first.from - days.days).rows.first.first }
      statements = []
      counter = ->(*, payload) { statements << payload[:sql] if payload[:sql].start_with?("WITH batch AS") }
      ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { described_class.ensure!(tables: [ receipts ]) }
      expect(statements.first).to include("ORDER BY \"received_at\" DESC LIMIT 1")
      expect(ids.map { |id| c.select_value("SELECT count(*) FROM #{receipts} WHERE id = #{id}") }).to eq([ 1, 1, 1 ])
    end
  end

  describe "skipped runs (review 2 of #239)" do
    let(:cache) { ActiveSupport::Cache::MemoryStore.new }

    before do
      allow(Rails).to receive(:cache).and_return(cache)
      allow(Rails.logger).to receive(:warn)
    end

    it "still reports what it finds, so the banner stays up, and says so once maintenance has been skipped for hours" do
      receipt(1.year.from_now)
      allow(described_class).to receive(:backup_running?).and_return(true)
      expect(described_class.maintain!).to eq("skipped" => "backup running")
      expect(described_class.attention.map(&:text)).to eq([ "#{described_class.label(receipts)}: the default partition has rows (the next maintenance run moves them)" ])

      later = 4.hours.from_now
      described_class.maintain!(now: later)
      expect(described_class.attention.map(&:text)).to include(a_string_starting_with("Partition maintenance has been skipped since "))
      expect(described_class.health(now: later)).to eq(:warning)

      allow(described_class).to receive(:backup_running?).and_return(false)
      described_class.maintain!(now: later)
      expect(described_class.attention.map(&:text)).not_to include(a_string_starting_with("Partition maintenance has been skipped"))
      expect(described_class.maintain!(dry_run: true)).to include("created" => {})
    end

    it "reports a run skipped for the lock too, and does nothing in a dry run" do
      allow(SessionLock).to receive(:hold).and_return(nil)
      expect(described_class.maintain!).to eq("skipped" => "another maintenance run is in progress")
      expect(cache.read(described_class::SKIPPED_KEY)).to be_present
      expect(described_class.maintain!(dry_run: true)).to eq("skipped" => "another maintenance run is in progress")
    end
  end

  describe Partitions::GuardCheck do
    it "treats CREATEROLE like a superuser before PostgreSQL 16" do
      c.execute("CREATE ROLE fleet_guard_check_spec NOLOGIN CREATEROLE")
      c.execute("SET LOCAL ROLE fleet_guard_check_spec")
      check = described_class.new(c)
      allow(check).to receive(:before16?).and_return(true)
      expect(check.problem).to eq("the app's PostgreSQL role has CREATEROLE, which before PostgreSQL 16 can grant itself any role")
    end
  end
end
