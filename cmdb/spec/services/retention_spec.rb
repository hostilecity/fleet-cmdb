require "rails_helper"

# Retention and pruning (NFR-2, DEC-07, P1-S10). The history tables are partitioned by time (ADR 0027, #195): retire!
# drops their partitions past the window, and prune! deletes rows only in a converted table's legacy partition (and in
# the tables that are not partitioned). The examples of prune! give each partitioned table a legacy partition, as the
# conversion leaves one, and date their rows in it.
RSpec.describe Retention do
  let(:now) { Time.utc(2026, 11, 1, 12, 0, 0) }
  let(:host) { create(:host) }
  let(:other) { create(:host) }
  let(:c) { ApplicationRecord.connection }
  # Every row the conversion keeps in a legacy partition has this stored_at (Partitions::Conversion).
  let(:legacy_at) { Time.utc(2000, 1, 1) }

  def snapshot(host, age_days, stored_at: legacy_at)
    at = now - age_days.days
    InventorySnapshot.create!(host:, stable: {}, stable_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid, collected_at: at, received_at: at, stored_at:)
  end

  def status_event(host, age_days, to: "online", stored_at: legacy_at)
    HostStatusEvent.create!(host:, to_status: to, reason: "heartbeat", occurred_at: now - age_days.days, stored_at:)
  end

  def receipt(host, age_days)
    InventoryReportReceipt.create!(host:, report_id: SecureRandom.uuid, received_at: now - age_days.days)
  end

  def package_snapshot(host, age_days)
    at = now - age_days.days
    PackageSnapshot.create!(host:, manager: "dpkg", package_count: 0, content_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid,
                            collected_at: at, received_at: at, stored_at: legacy_at)
  end

  def package_receipt(host, age_days)
    PackageReportReceipt.create!(host:, report_id: SecureRandom.uuid, received_at: now - age_days.days)
  end

  def config_snapshot(host, age_days)
    at = now - age_days.days
    ConfigSnapshot.create!(host:, facts: {}, content_hash: SecureRandom.hex(32), manifest_version: 1, report_id: SecureRandom.uuid,
                           collected_at: at, received_at: at, stored_at: legacy_at)
  end

  def config_receipt(host, age_days)
    ConfigReportReceipt.create!(host:, report_id: SecureRandom.uuid, received_at: now - age_days.days)
  end

  def report_request(host, age_days)
    at = now - age_days.days
    ReportRequest.create!(host:, report_type: "config", state: "expired", requested_by: create(:operator), requested_at: at,
                          expires_at: at + 1.hour, expired_at: at + 1.hour)
  end

  def refresh_attempt(age_days) = AdvisoryRefreshAttempt.create!(kind: "scheduled", started_at: now - age_days.days)

  def old_audit_entry(age_days)
    AuditEntry.create!(actor_type: "system", action: Audit::Actions::HOST_EDITED, changeset: {}, occurred_at: now - age_days.days)
  end

  # A legacy partition below each partitioned table's partitions, as a converted table has (MINVALUE to its cutover).
  def legacy_partitions!
    (Partitions::TABLES.keys - [ Partitions::AUDIT ]).each do |table|
      cutover = Partitions.list(table).reject(&:default?).first.from
      c.execute("CREATE TABLE #{table}_legacy PARTITION OF #{table} FOR VALUES FROM (MINVALUE) TO (#{c.quote(cutover)})")
    end
  end

  def partition_of(row) = c.select_value("SELECT tableoid::regclass::text FROM #{row.class.table_name} WHERE id = #{row.id}")

  describe ".prune!" do
    before { legacy_partitions! }

    it "deletes nothing from a partitioned table that has no legacy partition (retire! drops its partitions)" do
      fresh = InventorySnapshot.create!(host:, stable: {}, stable_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid,
                                        collected_at: now - 400.days, received_at: now - 400.days)
      snapshot(host, 300)
      c.execute("ALTER TABLE inventory_snapshots DETACH PARTITION inventory_snapshots_legacy")
      expect(described_class.prune!(now:)["inventory_snapshots"]).to eq(0)
      expect(InventorySnapshot.exists?(fresh.id)).to be(true)
    end

    it "deletes only inside the legacy partition, and keeps a host's old row there while it has none newer anywhere" do
      in_legacy = snapshot(host, 300)
      current = snapshot(host, 200, stored_at: Time.current) # moved forward earlier, or stored since the conversion
      only = snapshot(other, 250)

      expect(described_class.prune!(now:)["inventory_snapshots"]).to eq(1)
      expect([ in_legacy, current, only ].map { |row| InventorySnapshot.exists?(row.id) }).to eq([ false, true, true ])
      expect(partition_of(only)).to eq("inventory_snapshots_legacy")
    end

    it "keeps the newest advisory refresh attempt however old, since it holds the cool-down (review of #125)" do
      older = refresh_attempt(200)
      newest = refresh_attempt(120)
      expect(described_class.prune!(now:)["advisory_refresh_attempts"]).to eq(1)
      expect(AdvisoryRefreshAttempt.pluck(:id)).to eq([ newest.id ])
      expect(AdvisoryRefreshAttempt.exists?(older.id)).to be(false)
    end

    it "removes rows older than the window and keeps newer ones, by default 90 days" do
      old = [ snapshot(host, 120), snapshot(host, 100), status_event(host, 95, to: "stale"), receipt(host, 91),
              package_snapshot(host, 120), package_receipt(host, 91), config_snapshot(host, 120), config_receipt(host, 91),
              report_request(host, 91), refresh_attempt(91) ]
      kept = [ snapshot(host, 89), snapshot(host, 5), status_event(host, 10, to: "offline"), receipt(host, 6),
               package_snapshot(host, 89), package_receipt(host, 6), config_snapshot(host, 89), config_receipt(host, 6),
               report_request(host, 89), refresh_attempt(89) ]

      counts = described_class.prune!(now:)

      expect(counts).to eq("inventory_snapshots" => 2, "inventory_report_receipts" => 1, "package_snapshots" => 1,
                           "package_report_receipts" => 1, "config_snapshots" => 1, "config_report_receipts" => 1,
                           "cis_result_changes" => 0, "host_status_events" => 1, "report_requests" => 1,
                           "advisory_refresh_attempts" => 1, "vulnerability_findings" => 0)
      expect(old.map { |row| row.class.exists?(row.id) }).to all(be(false))
      expect(kept.map { |row| row.class.exists?(row.id) }).to all(be(true))
    end

    it "keeps report ids for 7 days, not the whole retention window: they only need to outlive retries (scale assessment)" do
      old = [ receipt(host, 8), package_receipt(host, 30), config_receipt(other, 89) ]
      kept = [ receipt(host, 6), package_receipt(host, 1), config_receipt(other, 6.9) ]
      allow(Rails.logger).to receive(:info)

      counts = described_class.prune!(now:)

      expect(counts.values_at("inventory_report_receipts", "package_report_receipts", "config_report_receipts")).to eq([ 1, 1, 1 ])
      expect(old.map { |row| row.class.exists?(row.id) }).to all(be(false))
      expect(kept.map { |row| row.class.exists?(row.id) }).to all(be(true))
      expect(Rails.logger).to have_received(:info).with(/older than 2026-08-03T12:00:00Z \(inventory_report_receipts older than 2026-10-25T12:00:00Z, package_report_receipts/)
    end

    it "prunes report ids by the retention window when that is shorter than 7 days" do
      expect(described_class.targets.find { |t| t.model == InventoryReportReceipt }.max_age).to eq(7.days)
      old = receipt(host, 6)
      expect(described_class.prune!(now:, window: 5.days)["inventory_report_receipts"]).to eq(1)
      expect(InventoryReportReceipt.exists?(old.id)).to be(false)
    end

    it "always keeps the newest package snapshot of each host, whatever its age (P2-S08)" do
      old = package_snapshot(host, 400)
      newest = package_snapshot(host, 200)
      only = package_snapshot(other, 365)

      described_class.prune!(now:)

      expect([ old, newest, only ].map { |row| PackageSnapshot.exists?(row.id) }).to eq([ false, true, true ])
    end

    it "prunes old CIS result changes but never the current results (P2-S06)" do
      allow(CisEvaluationJob).to receive(:perform_later)
      rule, = define_cis_rules(cis_rule_hash)
      change = ->(age_days) { CisResultChange.create!(host:, cis_rule: rule, to_result: "pass", occurred_at: now - age_days.days) }
      old, kept = change.(100), change.(10)
      current = CisResult.create!(host:, cis_rule: rule, result: "pass", evaluated_at: now - 200.days, changed_at: now - 200.days)

      expect(described_class.prune!(now:)["cis_result_changes"]).to eq(1)
      expect([ old, kept, current ].map { |row| row.class.exists?(row.id) }).to eq([ false, true, true ])
    end

    it "prunes findings resolved before the window, never open or reopened ones, however old (P2-S12)" do
      findings!(host, "high", state: "resolved")
      findings!(host, "low", state: "resolved")
      findings!(host, "critical")
      findings!(host, "medium", state: "reopened")
      old_resolved, recent_resolved, open, reopened = VulnerabilityFinding.order(:id).to_a
      old_resolved.update_columns(resolved_at: now - 100.days)
      recent_resolved.update_columns(resolved_at: now - 10.days)
      open.update_columns(first_seen_at: now - 400.days)
      reopened.update_columns(first_seen_at: now - 400.days, resolved_at: now - 300.days, reopened_at: now - 200.days)

      expect(described_class.prune!(now:)["vulnerability_findings"]).to eq(1)
      expect([ old_resolved, recent_resolved, open, reopened ].map { |row| VulnerabilityFinding.exists?(row.id) }).to eq([ false, true, true, true ])
    end

    it "opens a new finding when an advisory matches again after its resolved finding was pruned" do
      record = osv_record(id: "DSA-9001-1", package: "openssl", fixed: "3.5.1-1+deb13u1")
      import_advisories(record, full: true)
      vulnerable = debian_host(packages: [ [ "openssl", "3.5.0-1", "openssl" ] ])
      VulnerabilityMatcher.match!([ vulnerable.id ])
      finding = VulnerabilityFinding.sole
      finding.update_columns(state: "resolved", resolution: "fixed", resolved_at: now - 100.days)
      described_class.prune!(now:)
      expect(VulnerabilityFinding.count).to eq(0)

      VulnerabilityMatcher.match!([ vulnerable.id ])
      expect(VulnerabilityFinding.sole).to have_attributes(state: "open", resolved_at: nil, reopened_at: nil)
    end

    it "always keeps the newest config snapshot of each host, whatever its age (P2-S02)" do
      old = config_snapshot(host, 400)
      newest = config_snapshot(host, 200)
      only = config_snapshot(other, 365)

      described_class.prune!(now:)

      expect([ old, newest, only ].map { |row| ConfigSnapshot.exists?(row.id) }).to eq([ false, true, true ])
    end

    it "always keeps the newest snapshot and status event of each host, whatever their age" do
      old_snapshot = snapshot(host, 400)
      newest_snapshot = snapshot(host, 200)
      only_snapshot = snapshot(other, 365)
      old_event = status_event(host, 300, to: "stale")
      newest_event = status_event(host, 250, to: "offline")

      described_class.prune!(now:)

      expect(InventorySnapshot.where(host:).pluck(:id)).to eq([ newest_snapshot.id ])
      expect(InventorySnapshot.exists?(old_snapshot.id)).to be(false)
      expect(InventorySnapshot.exists?(only_snapshot.id)).to be(true)
      expect(HostStatusEvent.where(host:).pluck(:id)).to eq([ newest_event.id ])
      expect(HostStatusEvent.exists?(old_event.id)).to be(false)
    end

    it "keeps one of two snapshots received at the same instant" do
      first = snapshot(host, 200)
      second = InventorySnapshot.create!(host:, stable: {}, stable_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid,
                                         collected_at: first.collected_at, received_at: first.received_at)

      described_class.prune!(now:)

      expect(InventorySnapshot.where(host:).pluck(:id)).to eq([ second.id ])
    end

    it "does not touch audit entries, however old, and the database would refuse to" do
      ancient = old_audit_entry(400)
      snapshot(host, 120)

      described_class.prune!(now:)

      expect(AuditEntry.exists?(ancient.id)).to be(true)
      expect(described_class.targets.map(&:model)).not_to include(AuditEntry)
      expect { AuditEntry.where(id: ancient.id).delete_all }.to raise_error(ActiveRecord::StatementInvalid, /append-only/)
    end

    # Freshness is read from the import records, so they are kept however old, as the OSV imports are (P2-D06,
    # P2-S16); so is the current triage data, which is replaced only by an import.
    it "never prunes advisory imports, triage imports, or triage entries" do
      expect(described_class.targets.map(&:model)).not_to include(AdvisoryImport, TriageImport, TriageEntry)
    end

    it "uses the configured window" do
      snapshot(host, 40)
      keeper = snapshot(host, 3)
      Setting.update_retention_days!(30, actor: Audit::SYSTEM)

      described_class.prune!(now:)

      expect(InventorySnapshot.where(host:).pluck(:id)).to eq([ keeper.id ])
    end

    it "deletes in batches, each a separate short statement" do
      create_list(:host, 3).each { |h| 4.times { |n| snapshot(h, 100 + n) } } # 12 snapshots, 9 of them prunable
      deletes = []
      counter = ->(*, payload) { deletes << payload[:sql] if payload[:sql].start_with?("DELETE FROM \"inventory_snapshots\"") }

      counts = ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { described_class.prune!(now:, batch_size: 2) }

      expect(counts["inventory_snapshots"]).to eq(9)
      expect(deletes.size).to eq(5) # 2 + 2 + 2 + 2 + 1
      expect(InventorySnapshot.count).to eq(3)
    end

    it "makes no changes in a dry run, and reports what it would delete" do
      snapshot(host, 120)
      snapshot(host, 100)
      status_event(host, 100)
      status_event(host, 99, to: "stale")
      allow(Rails.logger).to receive(:info)

      counts = described_class.prune!(now:, dry_run: true)

      expect(counts).to include("inventory_snapshots" => 1, "host_status_events" => 1)
      expect(InventorySnapshot.count).to eq(2)
      expect(HostStatusEvent.count).to eq(2)
      expect(Rails.logger).to have_received(:info).with(/dry run, would delete inventory_snapshots=1 .*host_status_events=1/)
    end

    it "logs how many rows it deleted from each table" do
      snapshot(host, 120)
      snapshot(host, 1)
      allow(Rails.logger).to receive(:info)

      described_class.prune!(now:)

      expect(Rails.logger).to have_received(:info).with(/\A\[retention\] deleted inventory_snapshots=1 inventory_report_receipts=0 package_snapshots=0 package_report_receipts=0 config_snapshots=0 config_report_receipts=0 cis_result_changes=0 host_status_events=0 report_requests=0 advisory_refresh_attempts=0 vulnerability_findings=0 older than 2026-08-03T12:00:00Z/)
    end
  end

  describe ".retire!" do
    let(:t0) { Time.current }

    # Partitions back to 130 days before now, as a server that has run that long has them.
    before { Partitions.ensure!(from: t0 - 130.days) }

    # A row stored when it was received, `age` days before now.
    def stored_snapshot(host, age)
      at = t0 - age.days
      InventorySnapshot.create!(host:, stable: {}, stable_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid, collected_at: at, received_at: at, stored_at: at)
    end

    def stored_event(host, age, to:)
      HostStatusEvent.create!(host:, to_status: to, reason: "evaluation", occurred_at: t0 - age.days, stored_at: t0 - age.days)
    end

    def stored_receipt(host, age) = InventoryReportReceipt.create!(host:, report_id: SecureRandom.uuid, received_at: t0 - age.days)

    def ranges(table) = Partitions.list(table).reject(&:default?)

    it "drops every partition wholly past the window, keeping each host's newest row (moved forward, same id) and all rows in the window" do
      old = stored_snapshot(host, 120)
      kept_old = stored_snapshot(host, 100) # the host's newest snapshot past the window, but it has a newer one
      recent = stored_snapshot(host, 30)
      only = stored_snapshot(create(:host), 110) # the only snapshot of a host whose inventory has not changed since
      edge = stored_snapshot(other, 89.5)
      events = [ stored_event(host, 125, to: "stale"), stored_event(host, 115, to: "online") ]
      receipts = [ stored_receipt(host, 9), stored_receipt(host, 5) ]
      due = ranges("inventory_snapshots").count { |p| p.to <= t0 - 90.days }

      results = described_class.retire!(now: t0)

      expect(results["inventory_snapshots"]).to include("partitions" => due, "moved" => 1)
      expect(ranges("inventory_snapshots").map(&:to)).to all(be > t0 - 90.days)
      expect([ old, kept_old ].map { |row| InventorySnapshot.exists?(row.id) }).to eq([ false, false ])
      expect([ recent, only, edge ].map { |row| InventorySnapshot.exists?(row.id) }).to all(be(true))
      expect(InventorySnapshot.find(only.id)).to have_attributes(received_at: only.received_at, stored_at: be_within(1.second).of(t0))
      expect(partition_of(only)).to eq("inventory_snapshots_p#{Partitions.align(Partitions.table('inventory_snapshots'), t0).strftime('%Y%m%d')}")
      # The newest status event moved forward too; the older one went with its partition.
      expect(HostStatusEvent.where(host:).pluck(:id)).to eq([ events.last.id ])
      expect(results["host_status_events"]["moved"]).to eq(1)
      # Receipts are kept 7 days (plus up to a day: a day's partition goes once all of it is past).
      expect(InventoryReportReceipt.exists?(receipts.first.id)).to be(false)
      expect(InventoryReportReceipt.exists?(receipts.last.id)).to be(true)
      expect(ranges("inventory_report_receipts").map(&:to)).to all(be > t0 - 7.days)
      expect(Partitions.problems(now: t0)).to be_empty
    end

    it "moves kept rows forward in batches, each its own statement" do
      hosts = create_list(:host, 3)
      hosts.each { |h| stored_snapshot(h, 120) }
      updates = []
      counter = ->(*, payload) { updates << payload[:sql] if payload[:sql].start_with?("UPDATE \"inventory_snapshots\" SET stored_at") }

      results = ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { described_class.retire!(now: t0, batch_size: 2) }

      expect(results["inventory_snapshots"]["moved"]).to eq(3)
      expect(updates.size).to eq(2)
      expect(InventorySnapshot.where(host_id: hosts.map(&:id)).count).to eq(3)
    end

    # Run by Partitions.maintain! under the maintenance lock (#198): the lock is checked before each batch moved forward
    # and each drop, so a run that lost it stops there, with nothing of the batch or the drop done.
    it "checks the maintenance lock before each batch it moves forward, and stops once it is lost" do
      hosts = create_list(:host, 3)
      hosts.each { |h| stored_snapshot(h, 120) }
      updates = []
      counter = ->(*, payload) { updates << payload[:sql] if payload[:sql].start_with?("UPDATE \"inventory_snapshots\" SET stored_at") }
      still_held = -> { raise SessionLock::Lost, "gone" if updates.size == 1 }
      partitions = ranges("inventory_snapshots").size

      expect { ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { described_class.retire!(now: t0, batch_size: 2, still_held:) } }
        .to raise_error(SessionLock::Lost)
      expect(updates.size).to eq(1)
      expect(ranges("inventory_snapshots").size).to eq(partitions) # nothing dropped
    end

    it "retires the legacy partition once its cutover is past the window, moving the newest rows it holds forward" do
      first = ranges("config_snapshots").first.from
      c.execute("CREATE TABLE config_snapshots_legacy PARTITION OF config_snapshots FOR VALUES FROM (MINVALUE) TO (#{c.quote(first)})")
      at = first - 400.days
      legacy = ConfigSnapshot.create!(host:, facts: {}, content_hash: SecureRandom.hex(32), manifest_version: 1, report_id: SecureRandom.uuid,
                                      collected_at: at, received_at: at, stored_at: legacy_at)
      expect(partition_of(legacy)).to eq("config_snapshots_legacy")

      results = described_class.retire!(now: t0)

      expect(results["config_snapshots"]).to include("moved" => 1)
      expect(Partitions.legacy("config_snapshots")).to be_nil
      expect(ConfigSnapshot.find(legacy.id).received_at).to eq(legacy.received_at)
    end

    it "counts what it would retire in a dry run, and changes nothing" do
      stored_snapshot(host, 120)
      stored_snapshot(host, 110)
      before = Partitions.list("inventory_snapshots")
      allow(Rails.logger).to receive(:info)

      results = described_class.retire!(now: t0, dry_run: true)

      expect(results["inventory_snapshots"]).to include("rows" => 1, "moved" => 1)
      expect(Partitions.list("inventory_snapshots")).to eq(before)
      expect(InventorySnapshot.where(host:).count).to eq(2)
      expect(Rails.logger).to have_received(:info).with(/\[retention\] dry run, would retire partitions .*inventory_snapshots=\d+ \(1 rows, 1 moved forward\)/)
    end

    it "logs what it retired, and nothing when nothing is due" do
      stored_snapshot(host, 120)
      allow(Rails.logger).to receive(:info)
      described_class.retire!(now: t0)
      expect(Rails.logger).to have_received(:info).with(/\A\[retention\] retired partitions .*inventory_snapshots=\d+ \(\d+ rows, 1 moved forward\)/)

      expect(described_class.retire!(now: t0).values.sum { |r| r["partitions"] }).to eq(0)
      expect(Rails.logger).to have_received(:info).once
    end

    it "leaves a table whose lock it cannot get for the next run, and retires the others" do
      stored_snapshot(host, 120)
      stored_event(host, 120, to: "stale")
      allow(Rails.logger).to receive(:warn)
      allow(Partitions).to receive(:detach_and_drop!).and_call_original
      allow(Partitions).to receive(:detach_and_drop!).with("inventory_snapshots", anything, still_held: anything).and_raise(Partitions::Busy, "lock not granted in 3 tries of 150ms")

      results = described_class.retire!(now: t0)

      expect(results["inventory_snapshots"]["partitions"]).to eq(0)
      expect(results["host_status_events"]["partitions"]).to be_positive
      expect(Rails.logger).to have_received(:warn).with("[retention] inventory_snapshots: lock not granted in 3 tries of 150ms; the next run tries again")
    end

    it "skips a table that is not partitioned yet" do
      allow(Partitions).to receive(:partitioned?).and_return(false)
      expect(described_class.retire!(now: t0).values).to all(eq("partitions" => 0, "rows" => 0, "moved" => 0))
    end

    it "reports the cutoff of each table, and none for one it does not prune" do
      expect(described_class.cutoff_for("inventory_report_receipts", now: t0)).to eq(t0 - 7.days)
      expect(described_class.cutoff_for("inventory_snapshots", now: t0)).to eq(t0 - 90.days)
      expect(described_class.cutoff_for("hosts", now: t0)).to be_nil
    end
  end

  describe PartitionMaintenanceJob do
    it "maintains the partitions, and can be run as a dry run" do
      allow(Partitions).to receive(:maintain!).and_return("created" => {}, "retired" => {})
      described_class.perform_now
      described_class.perform_now(dry_run: true)
      expect(Partitions).to have_received(:maintain!).with(dry_run: false)
      expect(Partitions).to have_received(:maintain!).with(dry_run: true)
    end

    it "is scheduled hourly, and the nightly check daily, in every environment that runs jobs" do
      recurring = YAML.load_file(Rails.root.join("config/recurring.yml"), aliases: true)
      %w[production development].each do |env|
        expect(recurring.fetch(env)["partition_maintenance"]).to include("class" => "PartitionMaintenanceJob", "schedule" => "every hour at minute 23")
        expect(recurring.fetch(env).dig("partition_check", "class")).to eq("PartitionCheckJob")
      end
    end
  end

  describe PartitionCheckJob do
    it "logs rows without their host as an error, and says so when there are none" do
      allow(Rails.logger).to receive(:error)
      allow(Rails.logger).to receive(:info)
      expect(described_class.perform_now).to eq({})
      expect(Rails.logger).to have_received(:info).with("[partitions] check: no rows without their host or rule")

      InventoryReportReceipt.insert!({ host_id: 2_000_000_000, report_id: SecureRandom.uuid, received_at: Time.current })
      expect(described_class.perform_now).to eq("inventory_report_receipts.host_id" => 1)
      expect(Rails.logger).to have_received(:error).with("[partitions] rows with no matching host or rule: inventory_report_receipts.host_id=1")
    end

    it "keeps what it found for /health and the dashboard banner" do
      cache = ActiveSupport::Cache::MemoryStore.new
      allow(Rails).to receive(:cache).and_return(cache)
      InventoryReportReceipt.insert!({ host_id: 2_000_000_000, report_id: SecureRandom.uuid, received_at: Time.current })
      described_class.perform_now
      expect(Partitions.attention).to eq([ "inventory_report_receipts.host_id: 1 recent rows name a host or rule that does not exist (bin/rails partitions:check)" ])
    end
  end

  describe ".register" do
    it "lets a later phase add its own table, replacing an earlier registration of the same model" do
      original = described_class.targets.dup
      described_class.register(InventoryReportReceipt, time_column: :received_at)
      expect(described_class.targets.count { |target| target.model == InventoryReportReceipt }).to eq(1)

      receipt(host, 200)
      expect(described_class.prune!(now:)["inventory_report_receipts"]).to eq(1)
    ensure
      described_class.targets.replace(original)
    end
  end

  describe RetentionPruneJob do
    before { legacy_partitions! }

    it "prunes with the stored window" do
      snapshot(host, 120)
      snapshot(host, 1)

      expect { described_class.perform_now }.to change(InventorySnapshot, :count).from(2).to(1)
    end

    it "can be run as a dry run" do
      snapshot(host, 120)
      snapshot(host, 1)

      expect { described_class.perform_now(dry_run: true) }.not_to change(InventorySnapshot, :count)
    end

    it "is scheduled daily in every environment that runs jobs" do
      recurring = YAML.load_file(Rails.root.join("config/recurring.yml"), aliases: true)
      expect(recurring.fetch("production").dig("retention_pruning", "class")).to eq("RetentionPruneJob")
      expect(recurring.fetch("development").dig("retention_pruning", "class")).to eq("RetentionPruneJob")
    end
  end

  describe Setting do
    it "defaults the retention window to 90 days" do
      expect(described_class.retention_window).to eq(90.days)
    end

    it "changes it, audited, and ignores a repeated value" do
      expect { described_class.update_retention_days!("30", actor: Audit::SYSTEM) }.to change(AuditEntry, :count).by(1)
      expect(described_class.retention_window).to eq(30.days)
      expect(AuditEntry.last.changeset).to eq("retention.days" => [ 90, 30 ])
      expect { described_class.update_retention_days!(30, actor: Audit::SYSTEM) }.not_to change(AuditEntry, :count)
    end

    [ "", "abc", "6", "3651", nil, "30.5" ].each do |value|
      it "rejects #{value.inspect}" do
        expect { described_class.update_retention_days!(value, actor: Audit::SYSTEM) }.to raise_error(Setting::Invalid, /whole number of days from 7 to 3650/)
        expect(described_class.retention_window).to eq(90.days)
      end
    end
  end
end
