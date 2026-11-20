require "rails_helper"

# What the agent reports about applicability (FR-2.6, VT-APPLICABILITY, #258): written only when it changes.
RSpec.describe HostApplicability do
  let(:host) { enrolled_host.first }
  let(:now) { Time.zone.parse("2026-11-20 12:00:00") }

  def inventory(**fields) = Struct.new(:applicability).new({ "reboot_required" => nil, "reboot_packages" => [], "kernel_build" => nil }.merge(fields.transform_keys(&:to_s)))
  def package_report(in_use) = Struct.new(:in_use).new(in_use)

  def in_use(**fields)
    HostApplicability::IN_USE_DEFAULTS.merge("in_use_reported" => true, "library_scan" => "off", "listening_network" => [ "samba" ],
                                             "running_services" => %w[cron samba]).merge(fields.transform_keys(&:to_s))
  end

  # The row's physical version: unchanged when nothing was written.
  def xmin = described_class.connection.select_value("SELECT xmin::text FROM host_applicability WHERE host_id = #{host.id}")

  it "writes no row for a host with nothing to say" do
    expect(described_class.record_inventory!(host_id: host.id, report: inventory, now:)).to be(false)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(nil), now:)).to be(false)
    expect(described_class.where(host_id: host.id)).not_to exist
  end

  it "stores the reboot flag and writes again only when it changes" do
    expect(described_class.record_inventory!(host_id: host.id, report: inventory(reboot_required: true, reboot_packages: [ "libc6" ]), now:)).to be(true)
    row = host.reload.applicability
    expect(row).to have_attributes(reboot_required: true, reboot_packages: [ "libc6" ], reboot_changed_at: now, in_use_reported: false)
    version = xmin
    expect(described_class.record_inventory!(host_id: host.id, report: inventory(reboot_required: true, reboot_packages: [ "libc6" ]), now: now + 1.hour)).to be(false)
    expect(xmin).to eq(version)
    expect(row.reload.reboot_changed_at).to eq(now)
    expect(described_class.record_inventory!(host_id: host.id, report: inventory(kernel_build: "#1 SMP Debian 6.12.57-1"), now: now + 2.hours)).to be(true)
    expect(row.reload).to have_attributes(reboot_required: nil, reboot_packages: [], kernel_build: "#1 SMP Debian 6.12.57-1", reboot_changed_at: now + 2.hours)
  end

  it "stores what is in use and writes again only when it changes" do
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(in_use), now:)).to be(true)
    row = host.reload.applicability
    expect(row).to have_attributes(in_use_reported: true, listening_network: [ "samba" ], running_services: %w[cron samba],
                                   library_scan: "off", in_use_changed_at: now, reboot_required: nil)
    expect(row.packages_in_use).to eq(%w[cron samba])
    version = xmin
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(in_use), now: now + 1.hour)).to be(false)
    expect(xmin).to eq(version)

    scanned = in_use(library_scan: "ran", libraries: %w[libc6 libssl3t64], stale_libraries: [ "libssl3t64" ],
                     native_packages: %w[libc6 libidle libssl3t64 samba], library_scanned_at: now)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now: now + 2.hours)).to be(true)
    expect(row.reload.packages_in_use).to eq(%w[cron libc6 libssl3t64 samba])
    expect(row).to have_attributes(stale_libraries: [ "libssl3t64" ], library_scanned_at: now)
  end

  # Owner decision 2026-11-20 (review of #268, B1, B2): idle needs the scan and native code.
  describe "#provably_idle?" do
    let(:report) { Struct.new(:collected_at, :received_at).new(now - 30.minutes, now - 20.minutes) }
    let(:row) do
      described_class.new(host_id: host.id, **in_use(library_scan: "ran", libraries: [ "libc6" ], native_packages: %w[libc6 libidle samba],
                                                     listening_loopback: [ "chrony" ], running_services: [ "chrony" ],
                                                     library_scanned_at: now - 50.minutes))
    end

    def idle?(package, at: now, package_set: report) = row.provably_idle?(package, package_set:, now: at)

    it "calls a package idle only when the scan judged it native and found it unused" do
      expect(idle?("libidle")).to be(true)
      expect(idle?("libc6")).to be(false) # mapped
      expect(idle?("samba")).to be(false) # listening on the network
      expect(idle?("chrony")).to be(false) # not judged native, and a running service
      expect(idle?("python3-urllib3")).to be(false) # interpreted code: never judged
      row.assign_attributes(native_packages: [ "chrony" ], listening_network: [], listening_loopback: [ "chrony" ], running_services: [])
      expect(idle?("chrony")).to be(false) # listening on loopback
    end

    it "needs the scan to have run, whatever else the row holds" do # review of #268, N3
      row.library_scan = "failed"
      expect(idle?("libidle")).to be(false)
      row.library_scan = "off"
      expect(idle?("libidle")).to be(false)
    end

    # Review of #268, S5: a stale scan proves nothing.
    it "needs a fresh scan and a recent report" do
      expect(idle?("libidle", at: now + 11.hours)).to be(true)
      expect(idle?("libidle", at: now + 13.hours)).to be(false) # the report is more than 12 hours old
      row.library_scanned_at = report.collected_at - 3.hours # a scan far older than its report (a suspend, a clock jump)
      expect(idle?("libidle")).to be(false)
      row.library_scanned_at = report.collected_at + 1.hour # a scan after its report
      expect(idle?("libidle")).to be(false)
      row.library_scanned_at = nil
      expect(idle?("libidle")).to be(false)
      row.library_scanned_at = now - 50.minutes
      expect(idle?("libidle", package_set: nil)).to be(false)
      expect(idle?("libidle", package_set: Struct.new(:collected_at, :received_at).new(nil, now))).to be(false)
    end
  end

  it "does not count a new scan time alone as a change, but stores it" do # review of #268, N1
    scanned = in_use(library_scan: "ran", native_packages: [ "libidle" ], library_scanned_at: now)
    described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now:)
    later = scanned.merge("library_scanned_at" => now + 1.hour)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(later), now: now + 1.hour)).to be(false)
    expect(host.reload.applicability).to have_attributes(library_scanned_at: now + 1.hour, in_use_changed_at: now)
  end

  it "clears what is in use when a report has none, unreadable ones included, so nothing reads as idle" do
    described_class.record_in_use!(host_id: host.id, report: package_report(in_use), now:)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(nil), now: now + 1.hour)).to be(true)
    expect(host.reload.applicability).to have_attributes(in_use_reported: false, listening_network: [], running_services: [],
                                                        library_scan: nil, in_use_changed_at: now + 1.hour)
  end

  it "refuses a reboot flag of false and an unknown scan state in the database too" do
    expect { described_class.create!(host_id: host.id, reboot_required: false) }.to raise_error(ActiveRecord::StatementInvalid, /reboot_true_or_null/)
    expect(described_class.new(host_id: host.id, in_use_reported: true, library_scan: "maybe")).not_to be_valid
    expect { described_class.new(host_id: host.id, in_use_reported: true).save!(validate: false) }
      .to raise_error(ActiveRecord::StatementInvalid, /in_use_reported/)
  end
end
