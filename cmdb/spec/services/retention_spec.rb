require "rails_helper"

# Retention and pruning (NFR-2, DEC-07, P1-S10).
RSpec.describe Retention do
  let(:now) { Time.utc(2026, 11, 1, 12, 0, 0) }
  let(:host) { create(:host) }
  let(:other) { create(:host) }

  def snapshot(host, age_days)
    at = now - age_days.days
    InventorySnapshot.create!(host:, stable: {}, stable_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid, collected_at: at, received_at: at)
  end

  def status_event(host, age_days, to: "online")
    HostStatusEvent.create!(host:, to_status: to, reason: "heartbeat", occurred_at: now - age_days.days)
  end

  def receipt(host, age_days)
    InventoryReportReceipt.create!(host:, report_id: SecureRandom.uuid, received_at: now - age_days.days)
  end

  def package_snapshot(host, age_days)
    at = now - age_days.days
    PackageSnapshot.create!(host:, manager: "dpkg", package_count: 0, content_hash: SecureRandom.hex(32), packages: [], report_id: SecureRandom.uuid,
                            collected_at: at, received_at: at)
  end

  def package_receipt(host, age_days)
    PackageReportReceipt.create!(host:, report_id: SecureRandom.uuid, received_at: now - age_days.days)
  end

  def old_audit_entry(age_days)
    AuditEntry.create!(actor_type: "system", action: Audit::Actions::HOST_EDITED, changeset: {}, occurred_at: now - age_days.days)
  end

  describe ".prune!" do
    it "removes rows older than the window and keeps newer ones, by default 90 days" do
      old = [ snapshot(host, 120), snapshot(host, 100), status_event(host, 95, to: "stale"), receipt(host, 91),
              package_snapshot(host, 120), package_receipt(host, 91) ]
      kept = [ snapshot(host, 89), snapshot(host, 5), status_event(host, 10, to: "offline"), receipt(host, 89),
               package_snapshot(host, 89), package_receipt(host, 89) ]

      counts = described_class.prune!(now:)

      expect(counts).to eq("inventory_snapshots" => 2, "inventory_report_receipts" => 1, "package_snapshots" => 1,
                           "package_report_receipts" => 1, "host_status_events" => 1)
      expect(old.map { |row| row.class.exists?(row.id) }).to all(be(false))
      expect(kept.map { |row| row.class.exists?(row.id) }).to all(be(true))
    end

    it "always keeps the newest package snapshot of each host, whatever its age (P2-S08)" do
      old = package_snapshot(host, 400)
      newest = package_snapshot(host, 200)
      only = package_snapshot(other, 365)

      described_class.prune!(now:)

      expect([ old, newest, only ].map { |row| PackageSnapshot.exists?(row.id) }).to eq([ false, true, true ])
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
      ancient = old_audit_entry(2_000)
      snapshot(host, 120)

      described_class.prune!(now:)

      expect(AuditEntry.exists?(ancient.id)).to be(true)
      expect(described_class.targets.map(&:model)).not_to include(AuditEntry)
      expect { AuditEntry.where(id: ancient.id).delete_all }.to raise_error(ActiveRecord::StatementInvalid, /append-only/)
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

      expect(Rails.logger).to have_received(:info).with(/\A\[retention\] deleted inventory_snapshots=1 inventory_report_receipts=0 package_snapshots=0 package_report_receipts=0 host_status_events=0 older than 2026-08-03T12:00:00Z/)
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
