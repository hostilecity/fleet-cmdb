# Throwaway minisign keys and signed test releases (P1-RELEASES). Keys are generated per test run and never
# written anywhere; no private key is committed. TestReleaseKey signs exactly as minisign does in its default,
# pre-hashed mode (Ed25519 over BLAKE2b-512, plus the global signature over the signature and the trusted
# comment); spec/fixtures/releases holds a release signed by the real minisign implementation to prove the
# two agree.
class TestReleaseKey
  attr_reader :key_id

  # key_id: the 8 bytes as stored in the key (little-endian), random unless a spec needs a particular one.
  def initialize(key_id: SecureRandom.bytes(8))
    @pkey = OpenSSL::PKey.generate_key("ED25519")
    @key_id = key_id.b
  end

  # A key whose id, as a number, is id (for example 0x0A2E8E1D2E10F3B9).
  def self.with_id(id) = new(key_id: [ id ].pack("Q<"))

  # The base64 line of the minisign .pub file.
  def public_line = Base64.strict_encode64("Ed" + key_id + @pkey.raw_public_key)

  # The whole .pub file, as minisign 0.12 writes it.
  def public_file = "untrusted comment: minisign public key #{id_hex}\n#{public_line}\n"

  # As minisign 0.12 prints it, and Releases::PublicKey#id_hex: 16 uppercase hexadecimal digits.
  def id_hex = format("%016X", key_id.unpack1("Q<"))

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

  # Trusts the given keys (TestReleaseKey, or a .pub text) for the rest of the example, and publishes the same keys as
  # the repository's agent/release-keys (#181), as a correctly configured server has them.
  def trust_release_keys(current: release_key, next_key: nil)
    config = Rails.configuration.x.releases
    config.current_key = pub_text(current)
    config.next_key = pub_text(next_key)
    publish_repository_keys(current:, next_key:)
  end

  # Writes the repository's agent/release-keys/current.pub and next.pub, as this server's build has them. nil
  # writes a file of comments only, as the repository holds before the owner makes the keys.
  def publish_repository_keys(current: release_key, next_key: nil)
    dir = Rails.configuration.x.releases.repository_keys_dir
    { "current" => current, "next" => next_key }.each do |role, key|
      dir.join("#{role}.pub").write(pub_text(key) || "# no #{role} key yet\n")
    end
  end

  def pub_text(key) = key.respond_to?(:public_file) ? key.public_file : key

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
  # Every example starts with no trusted key, an empty release directory of its own, and a repository key directory
  # of its own (the real agent/release-keys is checked by spec/services/releases/repository_keys_spec.rb).
  config.around do |example|
    releases = Rails.configuration.x.releases
    saved = releases.to_h.slice(:current_key, :next_key, :storage_dir, :repository_keys_dir)
    Dir.mktmpdir("releases") do |dir|
      releases.current_key = nil
      releases.next_key = nil
      releases.storage_dir = Pathname(dir).join("releases")
      releases.repository_keys_dir = Pathname(dir).join("release-keys").tap(&:mkpath)
      example.run
    ensure
      saved.each { |key, value| releases.public_send(:"#{key}=", value) }
    end
  end
end
