module Releases
  # A minisign Ed25519 public key (ADR 0021): base64 of the algorithm ("Ed"), an 8-byte key id, and the
  # 32-byte key. Verification uses Ruby's OpenSSL, so no extra gem is needed.
  class PublicKey
    ALGORITHMS = [ "Ed", "ED" ].freeze # as minisign-verify accepts
    UNTRUSTED_COMMENT = "untrusted comment:".freeze

    attr_reader :role, :key_id

    # text: the two lines of a minisign .pub file, or only its base64 line; "#" lines and blank lines are
    # ignored, as in the agent's key files. Returns nil when nothing is left (no key). role: "current" or
    # "next".
    def self.parse(text, role:)
      lines = text.to_s.lines.map(&:strip).reject { |line| line.empty? || line.start_with?("#") }
      line = case lines
      in [] then return nil
      in [ String => key ] then key
      in [ String => comment, String => key ] if comment.start_with?(UNTRUSTED_COMMENT) then key
      else raise KeyError, "the #{role} release key is not the two lines of a minisign .pub file"
      end
      new(decode(line, role), role)
    end

    def self.decode(line, role)
      bytes = Base64.strict_decode64(line)
      raise ArgumentError unless bytes.bytesize == 42 && ALGORITHMS.include?(bytes.byteslice(0, 2))

      bytes
    rescue ArgumentError
      raise KeyError, "the #{role} release key is not a minisign Ed25519 public key"
    end
    private_class_method :decode

    def initialize(bytes, role)
      @key_id = bytes.byteslice(2, 8)
      @raw = bytes.byteslice(10, 32)
      @pkey = OpenSSL::PKey.new_raw_public_key("ED25519", @raw)
      @role = role
    end

    # The key id as minisign prints it ("minisign public key 9E62E8E1D2E10F3B"): the little-endian number
    # in uppercase hexadecimal.
    def id_hex = key_id.reverse.unpack1("H*").upcase

    def ==(other) = other.is_a?(PublicKey) && other.raw == raw && other.key_id == key_id

    # Whether signature is a valid Ed25519 signature of data by this key.
    def verify(signature, data) = @pkey.verify(nil, signature, data)

    protected

    attr_reader :raw
  end
end
