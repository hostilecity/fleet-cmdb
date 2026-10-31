# Throwaway minisign keys and signed test releases (P1-RELEASES). Keys are generated per test run and never
# written anywhere; no private key is committed. TestReleaseKey signs exactly as minisign does in its default,
# pre-hashed mode (Ed25519 over BLAKE2b-512, plus the global signature over the signature and the trusted
# comment); spec/fixtures/releases holds a release signed by the real minisign implementation to prove the
# two agree.
class TestReleaseKey
  attr_reader :key_id

  def initialize
    @pkey = OpenSSL::PKey.generate_key("ED25519")
    @key_id = SecureRandom.bytes(8)
  end

  # The base64 line of the minisign .pub file.
  def public_line = Base64.strict_encode64("Ed" + key_id + @pkey.raw_public_key)

  # The whole .pub file, as minisign writes it.
  def public_file = "untrusted comment: minisign public key #{key_id.reverse.unpack1('H*').upcase}\n#{public_line}\n"

  def id_hex = key_id.reverse.unpack1("H*").upcase

  # A .minisig for message. legacy: sign the message itself ("Ed"), not its hash.
  def sign(message, trusted_comment: "fleet-agent test release manifest", legacy: false, key_id: self.key_id)
    signed = legacy ? message : OpenSSL::Digest.digest("BLAKE2b512", message)
    signature = @pkey.sign(nil, signed)
    global = @pkey.sign(nil, signature + trusted_comment.b)
    "untrusted comment: signature from minisign secret key\n" \
      "#{Base64.strict_encode64((legacy ? 'Ed' : 'ED') + key_id + signature)}\n" \
      "trusted comment: #{trusted_comment}\n#{Base64.strict_encode64(global)}\n"
  end
end

module ReleaseHelpers
  TestRelease = Data.define(:version, :binary, :manifest, :signature) do
    def sha256 = OpenSSL::Digest::SHA256.hexdigest(binary)
  end

  def release_key = (@release_key ||= TestReleaseKey.new)

  def next_release_key = (@next_release_key ||= TestReleaseKey.new)

  # Trusts the given keys (TestReleaseKey, or a .pub text) for the rest of the example.
  def trust_release_keys(current: release_key, next_key: nil)
    config = Rails.configuration.x.releases
    config.current_key = current.respond_to?(:public_file) ? current.public_file : current
    config.next_key = next_key.respond_to?(:public_file) ? next_key.public_file : next_key
  end

  def manifest_json(version:, binary:, **overrides)
    { "format" => Releases::MANIFEST_FORMAT, "version" => version, "target" => Releases::TARGET,
      "sha256" => OpenSSL::Digest::SHA256.hexdigest(binary), "size" => binary.bytesize }.merge(overrides.transform_keys(&:to_s)).to_json
  end

  # A release signed by key (the trusted current key by default). The binary is random, so each is distinct.
  def signed_release(version: "1.2.0", key: release_key, binary: SecureRandom.bytes(4096), manifest: nil, **manifest_overrides)
    manifest ||= manifest_json(version:, binary:, **manifest_overrides)
    TestRelease.new(version:, binary:, manifest:,
                    signature: key.sign(manifest, trusted_comment: "fleet-agent #{version} #{Releases::TARGET} release manifest"))
  end

  # Imports a release as an operator would, through Releases::Import.
  def import_release(release = signed_release, operator: create(:operator), source: "upload")
    Releases::Import.new(operator:, source:).call(manifest: release.manifest, signature: release.signature) { StringIO.new(release.binary) }.release
  end
end

RSpec.configure do |config|
  config.include ReleaseHelpers
  # Every example starts with no trusted key and an empty release directory of its own.
  config.around do |example|
    releases = Rails.configuration.x.releases
    saved = releases.to_h.slice(:current_key, :next_key, :storage_dir)
    Dir.mktmpdir("releases") do |dir|
      releases.current_key = nil
      releases.next_key = nil
      releases.storage_dir = Pathname(dir).join("releases")
      example.run
    ensure
      saved.each { |key, value| releases.public_send(:"#{key}=", value) }
    end
  end
end
