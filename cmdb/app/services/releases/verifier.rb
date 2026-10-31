module Releases
  # Checks a release exactly as the agent does (agent/src/release/mod.rs, docs/releases.md "What an agent
  # accepts"), in the same order:
  #
  # 1. the signature verifies against one of the release public keys, in minisign's pre-hashed mode, and so
  #    does its global signature over the trusted comment;
  # 2. only then is the manifest parsed, and it must follow every rule of its format;
  # 3. the binary has exactly the manifest's size and SHA-256.
  module Verifier
    # A verified manifest. sha256 is lowercase hexadecimal, as in the manifest.
    Manifest = Data.define(:version, :target, :sha256, :size)
    Verified = Data.define(:manifest, :key, :trusted_comment)

    FIELDS = %w[format version target sha256 size].freeze
    SHA256_FORMAT = /\A[0-9a-f]{64}\z/
    CHUNK = 64.kilobytes

    module_function

    # Verifies signature (a .minisig file) over the exact bytes of manifest, then parses the manifest.
    # Returns a Verified, or raises Refused.
    def verify_manifest(manifest, signature, keys = Releases.keys)
      raise Refused, "no release public key is configured on this server (FLEET_RELEASE_KEY_CURRENT)" if keys.empty?
      raise Refused, "the manifest is larger than #{MAX_MANIFEST_BYTES} bytes" if manifest.bytesize > MAX_MANIFEST_BYTES
      raise Refused, "the signature is larger than #{MAX_SIGNATURE_BYTES} bytes" if signature.bytesize > MAX_SIGNATURE_BYTES

      parsed = Signature.parse(signature) or raise Refused, "the signature is not a minisign signature"
      key = keys.find { |candidate| candidate.key_id == parsed.key_id } or
        raise Refused, "the manifest is signed by a key this server does not trust"
      raise Refused, "the signature uses minisign's legacy mode, which is not accepted" unless parsed.prehashed?

      digest = OpenSSL::Digest.digest("BLAKE2b512", manifest)
      comment = parsed.trusted_comment.b
      unless key.verify(parsed.signature, digest) && key.verify(parsed.global_signature, parsed.signature + comment)
        raise Refused, "the manifest signature is not valid"
      end

      Verified.new(manifest: parse_manifest(manifest), key:, trusted_comment: parsed.trusted_comment)
    end

    # Reads io to its end, at most one byte more than the manifest's size, and checks the size and SHA-256.
    # Every byte read is also written to copy_to, if given. Raises Refused on a mismatch.
    def check_binary(manifest, io, copy_to: nil)
      digest = OpenSSL::Digest.new("SHA256")
      actual = 0
      limit = manifest.size + 1
      while actual < limit && (chunk = io.read([ CHUNK, limit - actual ].min))
        digest.update(chunk)
        copy_to&.write(chunk)
        actual += chunk.bytesize
      end
      raise Refused, "the binary is larger than the manifest's #{manifest.size} bytes" if actual > manifest.size
      raise Refused, "the binary is #{actual} bytes but the manifest says #{manifest.size}" if actual < manifest.size
      raise Refused, "the binary's SHA-256 does not match the manifest" unless digest.hexdigest == manifest.sha256

      true
    end

    # The manifest's rules (docs/releases.md "The manifest"). Only called once its signature has verified.
    def parse_manifest(bytes)
      text = bytes.dup.force_encoding(Encoding::UTF_8)
      raise EncodingError unless text.valid_encoding? # JSON is UTF-8; Ruby's parser would let it pass
      data = JSON.parse(text, allow_duplicate_key: false)
      bad = ->(why) { raise Refused, "the signed manifest is not valid: #{why}" }
      bad.("it is not a JSON object") unless data.is_a?(Hash)
      bad.("it has fields other than #{FIELDS.join(', ')}") unless (data.keys - FIELDS).empty?
      missing = FIELDS - data.keys
      bad.("it has no #{missing.first}") if missing.any?
      bad.("format, version, target, and sha256 must be strings") unless data.values_at(*FIELDS.first(4)).all?(String)
      bad.("unsupported format (this server reads #{MANIFEST_FORMAT})") unless data["format"] == MANIFEST_FORMAT
      bad.("the version is too long") if data["version"].length > MAX_VERSION_LENGTH
      bad.("the version is not a SemVer version such as 1.2.3") unless AgentApi::AgentVersion.parse(data["version"])
      bad.("the version has build metadata (`+...`)") if data["version"].include?("+")
      raise Refused, "the release is for another target, not #{TARGET}" unless data["target"] == TARGET
      bad.("sha256 is not 64 lowercase hexadecimal digits") unless data["sha256"].match?(SHA256_FORMAT)
      bad.("the size is not between 1 and #{MAX_BINARY_BYTES} bytes") unless data["size"].is_a?(Integer) && data["size"].between?(1, MAX_BINARY_BYTES)

      Manifest.new(version: data["version"], target: data["target"], sha256: data["sha256"], size: data["size"])
    rescue JSON::ParserError, EncodingError
      raise Refused, "the signed manifest is not valid: it is not JSON"
    end
  end
end
