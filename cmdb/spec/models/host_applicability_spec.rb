require "rails_helper"

# What the agent reports about applicability (FR-2.6, VT-APPLICABILITY, #258): written only when it changes.
RSpec.describe HostApplicability do
  let(:host) { enrolled_host.first }
  let(:now) { Time.zone.parse("2026-11-20 12:00:00") }

  def inventory(**fields) = Struct.new(:applicability).new({ "reboot_required" => nil, "reboot_packages" => [], "kernel_build" => nil }.merge(fields.transform_keys(&:to_s)))
  def package_report(in_use) = Struct.new(:in_use).new(in_use)
  def use(packages, listener, klass, service: nil, sockets: [ klass == "network" ? "0.0.0.0:22/tcp" : "127.0.0.1:22/tcp" ])
    { "listener" => listener, "service" => service, "class" => klass, "sockets" => sockets, "packages" => Array(packages) }
  end

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
                     loaded_by_listeners: [ use("libssl3t64", "samba", "network") ], library_scanned_at: now)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now: now + 2.hours)).to be(true)
    expect(row.reload.packages_in_use).to eq(%w[cron libc6 libssl3t64 samba])
    expect(row).to have_attributes(stale_libraries: [ "libssl3t64" ], library_scanned_at: now, library_scan_received_at: now + 2.hours,
                                   loaded_by_listeners: [ use("libssl3t64", "samba", "network") ])
    version = xmin
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now: now + 3.hours)).to be(false)
    expect(xmin).to eq(version)
    moved = scanned.merge("loaded_by_listeners" => [ use("libssl3t64", "samba", "loopback") ])
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(moved), now: now + 4.hours)).to be(true)
    expect(row.reload.in_use_changed_at).to eq(now + 4.hours)
    rebound = scanned.merge("loaded_by_listeners" => [ use("libssl3t64", "samba", "loopback", sockets: [ "127.0.0.1:445/tcp" ]) ])
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(rebound), now: now + 5.hours)).to be(true) # a socket changed
    expect(row.reload.in_use_changed_at).to eq(now + 5.hours)
  end

  # Owner decision 2026-11-21 (after the fourth review of #268): positive evidence only; a package a listening process
  # loads is escalated until 24 hours after the server received the report that carried the scan (fifth review, S5).
  describe "#in_use_by_listener?" do
    let(:row) do
      described_class.new(host_id: host.id, **in_use(library_scan: "ran", libraries: %w[libc6 libidle libssl3t64 zlib1g],
                                                     loaded_by_listeners: [ use("libc6", nil, "loopback"),
                                                                            use(%w[libc6 libssl3t64], "openssh-server", "network", service: "ssh.service"),
                                                                            use("zlib1g", "chrony", "loopback") ],
                                                     library_scanned_at: now - 50.minutes, library_scan_received_at: now - 40.minutes))
    end

    it "is true only for a package a listening process loads, and says which listeners" do
      expect(row.in_use_by_listener?("libc6", now:)).to be(true)
      expect(row.in_use_by_listener?("libc6", now:, network: true)).to be(true)
      expect(row.in_use_by_listener?("libssl3t64", now:, network: true)).to be(true)
      expect(row.in_use_by_listener?("zlib1g", now:)).to be(true)
      expect(row.in_use_by_listener?("zlib1g", now:, network: true)).to be(false) # loopback only
      expect(row.in_use_by_listener?("libidle", now:)).to be(false) # mapped, but by no listening process
      expect(row.in_use_by_listener?("python3-urllib3", now:)).to be(false) # not seen: simply not escalated
      expect(row.listener_details("libc6", now:)).to eq([ { "listener" => "openssh-server", "service" => "ssh.service", "class" => "network",
                                                            "sockets" => [ "0.0.0.0:22/tcp" ] },
                                                          { "listener" => nil, "service" => nil, "class" => "loopback", "sockets" => [ "127.0.0.1:22/tcp" ] } ])
      expect(row.listener_details("libidle", now:)).to eq([])
    end

    it "follows a new value of the column" do
      expect(row.in_use_by_listener?("libidle", now:)).to be(false)
      row.loaded_by_listeners = [ use("libidle", "nginx", "network") ]
      expect(row.in_use_by_listener?("libidle", now:)).to be(true)
      expect(row.in_use_by_listener?("libc6", now:)).to be(false)
    end

    it "expires 24 hours after the server received the scan, whatever the agent's clock says" do
      row.library_scan_received_at = now - 24.hours
      expect(row.in_use_by_listener?("libc6", now:)).to be(true)
      expect(row.in_use_by_listener?("libc6", now: now + 1)).to be(false)
      expect(row.listener_details("libc6", now: now + 1)).to eq([])
      row.library_scan_received_at = now - 1.hour
      row.library_scanned_at = now - 3.days # an agent clock behind
      expect(row.in_use_by_listener?("libc6", now:)).to be(true)
      row.library_scanned_at = now + 3.days # and ahead
      expect(row.in_use_by_listener?("libc6", now: now + 25.hours)).to be(false)
      row.library_scan_received_at = nil
      expect(row.in_use_by_listener?("libc6", now:)).to be(false)
    end

    it "needs the scan to have run, whatever else the row holds" do
      row.library_scan = "failed"
      expect(row.in_use_by_listener?("libc6", now:)).to be(false)
      row.library_scan = "off"
      expect(row.in_use_by_listener?("libc6", now:)).to be(false)
    end
  end

  it "starts the expiry when the server first receives a scan, not again for a report that reuses it" do # fifth review, S5
    skewed = now - 2.days # the agent's clock, two days behind
    scanned = in_use(library_scan: "ran", loaded_by_listeners: [ use("libc6", "samba", "network") ], library_scanned_at: skewed)
    described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now:)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now: now + 30.minutes)).to be(false)
    row = host.reload.applicability
    expect(row.library_scan_received_at).to eq(now)
    expect(row.in_use_by_listener?("libc6", now: now + 23.hours)).to be(true)
    expect(row.in_use_by_listener?("libc6", now: now + 24.hours + 1)).to be(false)
    described_class.record_in_use!(host_id: host.id, report: package_report(scanned.merge("library_scanned_at" => skewed + 1.hour)), now: now + 1.hour)
    expect(row.reload.library_scan_received_at).to eq(now + 1.hour)
    # A failed scan, or the scan turned off, drops the evidence at that report (fifth review, S2).
    described_class.record_in_use!(host_id: host.id, report: package_report(in_use(library_scan: "failed", library_scanned_at: now + 2.hours)), now: now + 2.hours)
    expect(row.reload.in_use_by_listener?("libc6", now: now + 2.hours)).to be(false)
    described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now: now + 3.hours)
    described_class.record_in_use!(host_id: host.id, report: package_report(in_use), now: now + 4.hours)
    expect(row.reload).to have_attributes(library_scan: "off", loaded_by_listeners: [], library_scan_received_at: nil)
  end

  it "does not count a new scan time alone as a change, but stores it" do # review of #268, N1
    scanned = in_use(library_scan: "ran", loaded_by_listeners: [ use("libc6", "samba", "network") ], library_scanned_at: now)
    described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now:)
    later = scanned.merge("library_scanned_at" => now + 1.hour)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(later), now: now + 1.hour)).to be(false)
    expect(host.reload.applicability).to have_attributes(library_scanned_at: now + 1.hour, in_use_changed_at: now)
  end

  it "clears what is in use when a report has none, unreadable ones included, so nothing stays escalated" do
    scanned = in_use(library_scan: "ran", loaded_by_listeners: [ use("libc6", "samba", "network") ], library_scanned_at: now)
    described_class.record_in_use!(host_id: host.id, report: package_report(scanned), now:)
    expect(described_class.record_in_use!(host_id: host.id, report: package_report(nil), now: now + 1.hour)).to be(true)
    row = host.reload.applicability
    expect(row).to have_attributes(in_use_reported: false, listening_network: [], running_services: [],
                                   library_scan: nil, loaded_by_listeners: [], in_use_changed_at: now + 1.hour)
    expect(row.in_use_by_listener?("libc6", now: now + 1.hour)).to be(false)
  end

  it "refuses a reboot flag of false and an unknown scan state in the database too" do
    expect { described_class.create!(host_id: host.id, reboot_required: false) }.to raise_error(ActiveRecord::StatementInvalid, /reboot_true_or_null/)
    expect(described_class.new(host_id: host.id, in_use_reported: true, library_scan: "maybe")).not_to be_valid
    expect { described_class.new(host_id: host.id, in_use_reported: true).save!(validate: false) }
      .to raise_error(ActiveRecord::StatementInvalid, /in_use_reported/)
    expect { described_class.create!(host_id: host.id, loaded_by_listeners: { "libc6" => "samba" }) }
      .to raise_error(ActiveRecord::StatementInvalid, /loaded_by_listeners_array/)
  end
end
