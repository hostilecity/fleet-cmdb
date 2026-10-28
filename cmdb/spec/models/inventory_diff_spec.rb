require "rails_helper"

# Field-level changes between snapshots for the host history (P1-D03).
RSpec.describe InventoryDiff do
  let(:before) { AgentApi::InventoryReport.new(inventory_example).stable }

  def changes(after) = described_class.between(before, after).map { |c| [ c.label, c.old, c.new ] }

  it "finds nothing between equal inventories" do
    expect(changes(before.deep_dup)).to eq([])
  end

  it "reports scalar changes with old and new values" do
    after = before.merge("kernel_version" => "6.13.0-example-amd64", "memory_total_bytes" => 16 * 1024**3)
    expect(changes(after)).to eq([ [ "Kernel", "6.12.0-example-amd64", "6.13.0-example-amd64" ], [ "Total memory", "8 GiB", "16 GiB" ] ])
  end

  it "reports a field becoming unreadable as nil" do
    expect(changes(before.merge("machine_id" => nil))).to eq([ [ "Machine ID", before["machine_id"], nil ] ])
  end

  it "shows an operating system version change even when the name is unchanged" do
    after = before.merge("os" => before["os"].merge("version_id" => "13.1"))
    expect(changes(after)).to eq([ [ "Operating system", "Debian GNU/Linux 13 (trixie) (debian 13)", "Debian GNU/Linux 13 (trixie) (debian 13.1)" ] ])
  end

  it "matches disks by mount and interfaces by name: added, removed, and changed" do
    after = before.deep_dup
    after["disks"] = after["disks"].reject { |d| d["mount"] == "/" } + [ { "mount" => "/data", "filesystem" => "xfs", "size_bytes" => 2 * 1024**4 } ]
    after["network_interfaces"].first["addresses"] = [ "192.0.2.11/24" ]
    expect(changes(after)).to eq([
      [ "Disk /", "ext4, 32 GiB", nil ],
      [ "Disk /data", nil, "xfs, 2 TiB" ],
      [ "Interface ens18", "192.0.2.10/24, 2001:db8::10/64 (default route)", "192.0.2.11/24 (default route)" ]
    ])
  end

  it "treats a whole list becoming unreadable as each entry removed" do
    expect(changes(before.merge("disks" => nil)).map(&:first)).to eq([ "Disk /", "Disk /srv/media files" ])
  end
end
