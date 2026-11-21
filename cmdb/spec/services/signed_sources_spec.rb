require "rails_helper"

# The signed-template source table (#270, config/signed_sources.yml): what a package is matched as, and the checks
# that stop the server from starting with a bad table.
RSpec.describe SignedSources do
  def resolve(name, source, version, ecosystem: "Debian:13") = described_class.resolve(ecosystem, name, source, version).to_h

  describe ".resolve, with the repository's table and package names and versions from Debian 13" do
    it "matches the signed kernel image and its metapackage as linux at their own version, which is linux's" do
      # linux-signed-amd64 6.12.48+1 says "Sign kernel from linux 6.12.48-1" and builds its binaries with -v6.12.48-1.
      expect(resolve("linux-image-6.12.48+deb13-amd64", "linux-signed-amd64", "6.12.48-1")).to eq(source: "linux", version: "6.12.48-1", problem: nil)
      expect(resolve("linux-image-amd64", "linux-signed-amd64", "6.12.48-1")).to eq(source: "linux", version: "6.12.48-1", problem: nil)
      expect(resolve("linux-image-6.12.107+deb13-arm64", "linux-signed-arm64", "6.12.107-1")).to eq(source: "linux", version: "6.12.107-1", problem: nil)
    end

    it "matches shim-signed as shim at the shim version after its own" do
      expect(resolve("shim-signed", "shim-signed", "1.47+15.8-1")).to eq(source: "shim", version: "15.8-1", problem: nil)
      expect(resolve("shim-signed", "shim-signed", "1.51~1+deb13u1+16.1-2~deb13u1")).to eq(source: "shim", version: "16.1-2~deb13u1", problem: nil)
    end

    it "leaves shim-signed not evaluable when more than one + could start the shim version" do
      # shim-signed 1.32 was built from shim 15+1533136590.3beb971-5: 1.32+15+1533136590.3beb971-5.
      expect(resolve("shim-signed", "shim-signed", "1.32+15+1533136590.3beb971-5"))
        .to eq(source: "shim", version: nil, problem: "the shim version built into shim-signed 1.32+15+1533136590.3beb971-5 cannot be read from it " \
                                                       "(shim-signed: <shim-signed version>+<shim version>)")
      expect(resolve("shim-signed", "shim-signed", "16.1-2")[:problem]).to be_present # no signed version before it
    end

    it "keeps everything else as reported: a binary the row does not cover, the packages left out, and other ecosystems" do
      expect(resolve("shim-signed-common", "shim-signed", "1.51~1+deb13u1+16.1-2~deb13u1")).to eq(source: "shim-signed", version: "1.51~1+deb13u1+16.1-2~deb13u1", problem: nil)
      expect(resolve("grub-efi-amd64-signed", "grub-efi-amd64-signed", "1+2.12+9+deb13u2")).to eq(source: "grub-efi-amd64-signed", version: "1+2.12+9+deb13u2", problem: nil)
      expect(resolve("fwupd-amd64-signed", "fwupd-amd64-signed", "1:1.7+1")).to eq(source: "fwupd-amd64-signed", version: "1:1.7+1", problem: nil)
      expect(resolve("linux-libc-dev", "linux", "6.12.48-1")).to eq(source: "linux", version: "6.12.48-1", problem: nil)
      expect(resolve("openssl", nil, "3.5.0-1")).to eq(source: "openssl", version: "3.5.0-1", problem: nil) # its own source
      expect(resolve("linux-image-amd64", "linux-signed-amd64", "6.12.48-1", ecosystem: "Alpine:v3.22")[:source]).to eq("linux-signed-amd64")
    end
  end

  it "lists the reported sources an advisory change to some sources touches, and the sources the table maps to" do
    expect(described_class.reported(%w[linux openssl], "Debian:13")).to eq(%w[linux openssl linux-signed-amd64 linux-signed-arm64])
    expect(described_class.reported(%w[shim])).to eq(%w[shim shim-signed])
    expect(described_class.reported(%w[openssl], "Alpine:v3.22")).to eq(%w[openssl])
    expect(described_class.sources("Debian:13")).to eq(%w[linux shim])
    expect(described_class.sources("Alpine:v3.22")).to eq([])
  end

  describe ".load" do
    let(:dir) { Pathname(Dir.mktmpdir("signed-sources-")) }

    after { FileUtils.rm_rf(dir) }

    def load(text)
      file = dir.join("signed_sources.yml")
      file.write(text)
      described_class.load(file)
    end

    it "loads the repository's table" do
      table = described_class.load(Rails.root.join("config/signed_sources.yml"))
      expect(table.keys).to eq([ "Debian" ])
      expect(table["Debian"]["shim-signed"]).to have_attributes(source: "shim", version: "after_signed_version", binaries: [ "shim-signed" ])
      expect(table).to be_frozen
    end

    it "refuses a table that is not a map of families to rows, a bad row, or a source listed twice" do
      expect { load("") }.to raise_error(/must map an ecosystem family/)
      expect { load("- linux") }.to raise_error(/must map an ecosystem family/)
      expect { load("Debian: linux") }.to raise_error(/Debian must be a list/)
      expect { load("'Debian 13': []") }.to raise_error(/must be a list/)
      [ "[ linux ]", "[ { signed: linux-signed-amd64, source: linux } ]", "[ { signed: linux-signed-amd64, source: linux, version: newest } ]",
        "[ { signed: Linux, source: linux, version: binary } ]", "[ { signed: linux, source: linux, version: binary } ]",
        "[ { signed: shim-signed, source: shim, version: binary, binaries: [] } ]", "[ { signed: shim-signed, source: shim, version: binary, binaries: [ 7 ] } ]",
        "[ { signed: shim-signed, source: shim, version: binary, binaries: shim-signed } ]",
        "[ { signed: shim-signed, source: shim, version: binary, note: x } ]" ].each do |rows|
        expect { load("Debian: #{rows}") }.to raise_error(/must have a signed and a source package name/), rows
      end
      expect { load("Debian: [ { signed: s, source: a, version: binary }, { signed: s, source: b, version: binary } ]") }.to raise_error(/s is listed twice/)
    end
  end
end
