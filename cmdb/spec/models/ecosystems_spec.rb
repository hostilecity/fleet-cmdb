require "rails_helper"

# The fleet profile's advisory ecosystems (DEC-01, DEC-11).
RSpec.describe Ecosystems do
  it "maps Debian 13 from an inventory's os, and nothing else" do
    expect(described_class.for_os("id" => "debian", "version_id" => "13", "pretty_name" => "Debian GNU/Linux 13 (trixie)")).to eq("Debian:13")
    expect(described_class.for_os("id" => "Debian", "version_id" => "13")).to eq("Debian:13")
    expect(described_class.for_os("id" => "debian", "version_id" => "12")).to be_nil
    expect(described_class.for_os("id" => "ubuntu", "version_id" => "24.04")).to be_nil
    expect(described_class.for_os(nil)).to be_nil
  end

  it "lists the supported ecosystems and their package manager" do
    expect(described_class.supported).to eq([ "Debian:13" ])
    expect(described_class).to be_supported("Debian:13")
    expect(described_class).not_to be_supported("Debian:12")
    expect(described_class.manager("Debian:13")).to eq("dpkg")
  end
end
