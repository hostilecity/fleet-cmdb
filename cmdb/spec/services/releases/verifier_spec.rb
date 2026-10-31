require "rails_helper"

# P1-S15, ADR 0018, ADR 0021: the server checks a release the way the agent does (agent/src/release/mod.rs).
RSpec.describe Releases::Verifier do
  def verify(release, keys: Releases.keys) = described_class.verify_manifest(release.manifest, release.signature, keys)

  # The reason a release (or the block) is refused; fails the example if it is accepted.
  def refusal(release = nil, keys: Releases.keys, &block)
    block ||= -> { verify(release, keys:) }
    block.call
    raise RSpec::Expectations::ExpectationNotMetError, "expected a refusal"
  rescue Releases::Refused => e
    e.message
  end

  before { trust_release_keys }

  describe "a release signed by the release key" do
    it "verifies, and says which key and trusted comment" do
      release = signed_release(version: "1.2.0")
      verified = verify(release)
      expect(verified.manifest).to have_attributes(version: "1.2.0", target: Releases::TARGET, sha256: release.sha256, size: 4096)
      expect(verified.key).to have_attributes(role: "current", id_hex: release_key.id_hex)
      expect(verified.trusted_comment).to eq("fleet-agent 1.2.0 #{Releases::TARGET} release manifest")
      expect(described_class.check_binary(verified.manifest, StringIO.new(release.binary))).to be(true)
    end

    it "verifies one signed by the real minisign implementation (spec/fixtures/releases/minisign)" do
      dir = Rails.root.join("spec/fixtures/releases/minisign")
      name = dir.join("fleet-agent-0.3.0-#{Releases::TARGET}")
      trust_release_keys(current: dir.join("release-key.pub").read)
      verified = described_class.verify_manifest(File.binread("#{name}.manifest.json"), File.binread("#{name}.manifest.json.minisig"))
      expect(verified.manifest.version).to eq("0.3.0")
      expect(verified.key.id_hex).to eq("63FD0DF857221279") # as minisign prints it in the .pub comment
      expect(described_class.check_binary(verified.manifest, File.open(name, "rb"))).to be(true)
    end

    it "verifies with the next key, so a key rotation works (ADR 0018)" do
      trust_release_keys(current: release_key, next_key: next_release_key)
      verified = verify(signed_release(key: next_release_key))
      expect(verified.key.role).to eq("next")
      expect(verify(signed_release(key: release_key)).key.role).to eq("current")
    end

    it "keeps verifying with keys given as the base64 line only" do
      trust_release_keys(current: "# a note\n#{release_key.public_line}\n")
      expect(verify(signed_release).key.role).to eq("current")
    end
  end

  describe "refusals" do
    it "refuses a wrong signature" do
      release = signed_release
      other = signed_release
      expect(refusal(release.with(signature: other.signature))).to eq("the manifest signature is not valid")
    end

    it "refuses a manifest changed after signing" do
      release = signed_release
      tampered = release.manifest.sub(release.sha256, "0" * 64)
      expect(refusal(release.with(manifest: tampered))).to eq("the manifest signature is not valid")
    end

    it "refuses a changed trusted comment, through the global signature" do
      release = signed_release
      forged = release.signature.sub(/^trusted comment: .*$/, "trusted comment: fleet-agent 9.9.9 release manifest")
      expect(refusal(release.with(signature: forged))).to eq("the manifest signature is not valid")
    end

    it "refuses a signature whose global signature is not over its own signature" do
      release = signed_release
      lines = release.signature.lines
      lines[3] = signed_release.signature.lines[3]
      expect(refusal(release.with(signature: lines.join))).to eq("the manifest signature is not valid")
    end

    it "refuses an unknown key, even one claiming a trusted key id" do
      expect(refusal(signed_release(key: TestReleaseKey.new))).to eq("the manifest is signed by a key this server does not trust")
      impostor = TestReleaseKey.new
      release = signed_release(key: impostor)
      claimed = release.with(signature: impostor.sign(release.manifest, key_id: release_key.key_id))
      expect(refusal(claimed)).to eq("the manifest signature is not valid")
    end

    it "refuses the next key's signature while only the current key is trusted" do
      expect(refusal(signed_release(key: next_release_key))).to eq("the manifest is signed by a key this server does not trust")
    end

    it "refuses minisign's legacy (not pre-hashed) mode" do
      release = signed_release
      legacy = release.with(signature: release_key.sign(release.manifest, legacy: true))
      expect(refusal(legacy)).to eq("the signature uses minisign's legacy mode, which is not accepted")
    end

    it "refuses everything when no key is configured" do
      trust_release_keys(current: nil)
      expect(refusal(signed_release)).to eq("no release public key is configured on this server (FLEET_RELEASE_KEY_CURRENT)")
    end

    it "refuses what is not a minisign signature" do
      release = signed_release
      lines = release.signature.lines
      [ "", "garbage", "\xFF\xFE".b, lines.first(3).join, lines.values_at(0, 1, 1, 3).join,
        lines.values_at(0, 1, 2).join + "not base64!\n",
        lines[0] + Base64.strict_encode64("ED#{'x' * 50}") + "\n" + lines[2..].join,
        release.signature.sub(lines[1].strip, Base64.strict_encode64("XX" + Base64.strict_decode64(lines[1].strip)[2..])),
        lines.values_at(0, 1, 2).join + Base64.strict_encode64("x" * 63) + "\n" ].each do |signature|
        expect(refusal(release.with(signature:))).to eq("the signature is not a minisign signature"), signature.inspect
      end
    end

    it "refuses an oversized manifest or signature before reading it" do
      release = signed_release
      expect(refusal(release.with(manifest: "x" * 4097))).to eq("the manifest is larger than 4096 bytes")
      expect(refusal(release.with(signature: "x" * 4097))).to eq("the signature is larger than 4096 bytes")
    end
  end

  describe "the manifest's rules (checked only after the signature verifies)" do
    def manifest_refusal(manifest) = refusal(signed_release(manifest:))

    it "requires a strict SemVer version without build metadata" do
      { "1.2" => "is not a SemVer version", "v1.2.0" => "is not a SemVer version", "01.2.0" => "is not a SemVer version",
        "1.2.0-rc.01" => "is not a SemVer version", "1.2.0-" => "is not a SemVer version", "1.2.0+build.5" => "has build metadata",
        "1.2.3-#{'a' * 60}" => "is too long", " 1.2.0" => "is not a SemVer version" }.each do |version, why|
        expect(manifest_refusal(manifest_json(version:, binary: "x"))).to include("the version #{why}"), version
      end
      expect(verify(signed_release(version: "1.3.0-rc.1")).manifest.version).to eq("1.3.0-rc.1")
    end

    it "refuses unknown, missing, duplicated, and mistyped fields" do
      base = JSON.parse(manifest_json(version: "1.2.0", binary: "x"))
      expect(manifest_refusal(base.merge("extra" => 1).to_json)).to include("fields other than")
      expect(manifest_refusal(base.except("size").to_json)).to include("it has no size")
      expect(manifest_refusal(base.to_json.sub("{", '{"version":"9.9.9",'))).to include("it is not JSON")
      expect(manifest_refusal(base.merge("version" => 1).to_json)).to include("must be strings")
      expect(manifest_refusal(base.merge("size" => 1.0).to_json)).to include("the size is not between")
      expect(manifest_refusal(base.merge("size" => "1").to_json)).to include("the size is not between")
      expect(manifest_refusal("[1]")).to include("it is not a JSON object")
      expect(manifest_refusal("not json")).to include("it is not JSON")
      expect(manifest_refusal("{\"format\":\"\xFF\"}".b)).to include("it is not JSON")
    end

    it "refuses another format, another target, a malformed checksum, and an impossible size" do
      binary = "x"
      expect(manifest_refusal(manifest_json(version: "1.2.0", binary:, format: "fleet-agent-release-manifest/2"))).to include("unsupported format")
      expect(manifest_refusal(manifest_json(version: "1.2.0", binary:, target: "aarch64-unknown-linux-musl"))).to eq("the release is for another target, not #{Releases::TARGET}")
      expect(manifest_refusal(manifest_json(version: "1.2.0", binary:, sha256: "A" * 64))).to include("sha256 is not 64 lowercase hexadecimal digits")
      expect(manifest_refusal(manifest_json(version: "1.2.0", binary:, size: 0))).to include("the size is not between 1 and 67108864 bytes")
      expect(manifest_refusal(manifest_json(version: "1.2.0", binary:, size: 64.megabytes + 1))).to include("the size is not between")
    end
  end

  describe ".check_binary" do
    let(:release) { signed_release }
    let(:manifest) { verify(release).manifest }

    it "refuses a modified binary of the same size" do
      modified = release.binary.dup.tap { |b| b.setbyte(100, b.getbyte(100) ^ 1) }
      expect(refusal { described_class.check_binary(manifest, StringIO.new(modified)) }).to eq("the binary's SHA-256 does not match the manifest")
    end

    it "refuses a shorter or longer binary, reading at most one byte past the size" do
      expect(refusal { described_class.check_binary(manifest, StringIO.new(release.binary[0...-1])) }).to eq("the binary is 4095 bytes but the manifest says 4096")
      longer = StringIO.new(release.binary + "x" * 100_000)
      expect(refusal { described_class.check_binary(manifest, longer) }).to eq("the binary is larger than the manifest's 4096 bytes")
      expect(longer.pos).to eq(4097)
    end

    it "copies what it read" do
      copy = StringIO.new(+"".b)
      described_class.check_binary(manifest, StringIO.new(release.binary), copy_to: copy)
      expect(copy.string).to eq(release.binary)
    end
  end

  describe "the configured keys (Releases.keys, the agent's rules)" do
    it "is empty without keys, and refuses a next key alone, the same key twice, or a malformed key" do
      trust_release_keys(current: nil)
      expect(Releases.keys).to eq([])
      trust_release_keys(current: "# no key yet\n\n")
      expect(Releases.keys).to eq([])
      trust_release_keys(current: nil, next_key: next_release_key)
      expect { Releases.keys }.to raise_error(Releases::KeyError, /without FLEET_RELEASE_KEY_CURRENT/)
      trust_release_keys(current: release_key, next_key: release_key.public_line)
      expect { Releases.keys }.to raise_error(Releases::KeyError, /are the same key/)
      [ "not base64", Base64.strict_encode64("Ed" + "x" * 30), Base64.strict_encode64("XX" + "x" * 40),
        "a\nb\nc", "comment without the prefix\n#{release_key.public_line}" ].each do |text|
        trust_release_keys(current: text)
        expect { Releases.keys }.to raise_error(Releases::KeyError, /current release key/), text
      end
    end

    it "answers false, not an error, for a signature of the wrong length" do
      key = Releases::PublicKey.parse(release_key.public_line, role: "current")
      expect(key.verify("x" * 10, "data")).to be(false)
    end
  end
end
