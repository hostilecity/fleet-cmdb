module Releases
  # A minisign signature file (.minisig), read the way minisign-verify's Signature::decode reads it:
  #
  #   untrusted comment: <anything>
  #   base64(algorithm "ED" or "Ed", 8-byte key id, 64-byte Ed25519 signature)
  #   trusted comment: <text>
  #   base64(64-byte Ed25519 signature of the signature and the trusted comment's text)
  #
  # "ED" is the pre-hashed mode (the signature is over the BLAKE2b-512 hash of the file), "Ed" the legacy mode,
  # which is read here but refused by the verifier. Lines after the fourth are ignored, as there.
  class Signature
    PREHASHED = "ED".freeze
    LEGACY = "Ed".freeze
    TRUSTED_COMMENT = "trusted comment: ".freeze

    attr_reader :key_id, :signature, :trusted_comment, :global_signature

    # A Signature, or nil when bytes are not a minisign signature.
    def self.parse(bytes)
      text = bytes.to_s.dup.force_encoding(Encoding::UTF_8)
      return nil unless text.valid_encoding?

      _untrusted, first, trusted, second = text.each_line(chomp: true).first(4)
      return nil unless second && trusted.start_with?(TRUSTED_COMMENT)

      signature = Base64.strict_decode64(first)
      global = Base64.strict_decode64(second)
      algorithm = signature.byteslice(0, 2)
      return nil unless signature.bytesize == 74 && global.bytesize == 64 && [ PREHASHED, LEGACY ].include?(algorithm)

      new(algorithm:, key_id: signature.byteslice(2, 8), signature: signature.byteslice(10, 64),
          trusted_comment: trusted.delete_prefix(TRUSTED_COMMENT), global_signature: global)
    rescue ArgumentError # not base64
      nil
    end

    def initialize(algorithm:, key_id:, signature:, trusted_comment:, global_signature:)
      @algorithm = algorithm
      @key_id = key_id
      @signature = signature
      @trusted_comment = trusted_comment
      @global_signature = global_signature
    end

    def prehashed? = @algorithm == PREHASHED
  end
end
