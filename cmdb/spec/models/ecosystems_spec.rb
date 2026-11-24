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

  # #274: trixie-backports builds come from forky's versions; OSV lists the ~bpo13 builds under Debian:14.
  it "keeps the ecosystem the fleet's backports are built from, and tells a backport from the release's own packages" do
    expect(described_class.imported).to eq(%w[Debian:13 Debian:14])
    expect(described_class).to be_imported("Debian:14")
    expect(described_class).not_to be_imported("Debian:12")
    expect(described_class).not_to be_supported("Debian:14")
    expect(described_class.backports_from("Debian:13")).to eq("Debian:14")
    expect(described_class.backports_from("Debian:14")).to be_nil
    expect(described_class.backports_into("Debian:14")).to eq([ "Debian:13" ])
    expect(described_class.backports_into("Debian:13")).to eq([])
    expect(described_class).to be_backport("Debian:13", "7.0.9-1~bpo13+1")
    expect(described_class).not_to be_backport("Debian:13", "6.12.38-1~bpo12+1") # bookworm-backports: built from trixie's version
    expect(described_class).not_to be_backport("Debian:13", "6.12.48-1")
    expect(described_class).not_to be_backport("Debian:14", "7.0.9-1~bpo13+1")
    expect(described_class.backport_like_sql("Debian:13")).to eq("version LIKE '%~bpo%' AND version LIKE '%~bpo13+%'")
    expect(described_class.backport_like_sql("Debian:14")).to be_nil
    expect(described_class.manager("Debian:14")).to eq("dpkg")
    expect(described_class.display_name("Debian:14")).to eq("Debian 14 (forky)")
  end
end
