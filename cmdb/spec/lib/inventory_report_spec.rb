require "rails_helper"

# The checks AgentApi::InventoryReport applies beyond the schema. The schema already rejects most bad
# addresses; these checks are the server's own backstop.
RSpec.describe AgentApi::InventoryReport do
  let(:full) { ApiContract.examples.find { |e| e.schema_name == "inventory.request" && e.name == "full" }.data }

  def with_addresses(*addresses)
    full.merge("network_interfaces" => [ { "name" => "ens18", "primary" => true, "addresses" => addresses } ])
  end

  it "rejects addresses that are not CIDRs or whose prefix does not fit the family" do
    %w[192.0.2.1/33 2001:db8::1/129 999.0.2.1/24 192.0.2.1 not-an-ip/24 192.0.2.1/x].each do |address|
      expect { described_class.new(with_addresses(address)) }.to raise_error(AgentApi::ValidationFailed) { |e|
        expect(e.details.pluck("pointer")).to eq([ "/network_interfaces/0/addresses/0" ])
      }, address
    end
  end

  it "normalises addresses so equal inventories hash equally" do
    a = described_class.new(with_addresses("2001:DB8:0::10/64", "192.0.2.10/24"))
    b = described_class.new(with_addresses("192.0.2.10/24", "2001:db8::10/64"))
    expect(a.stable["network_interfaces"].first["addresses"]).to eq(%w[192.0.2.10/24 2001:db8::10/64])
    expect(a.stable_hash).to eq(b.stable_hash)
  end

  it "keeps volatile fields out of the stable hash" do
    a = described_class.new(full)
    b = described_class.new(full.merge("memory_available_bytes" => 1, "uptime_seconds" => 2,
                                       "disks" => full["disks"].map { |d| d.merge("free_bytes" => 3) }))
    expect(a.stable_hash).to eq(b.stable_hash)
    expect(a.volatile).not_to eq(b.volatile)
  end
end
