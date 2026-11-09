module SecondFactors
  # Recovery codes (P3-S09, Q25, Q28): 10 random codes of 10 characters, shown once and stored only as HMAC-SHA256
  # keyed from FLEET_ENCRYPTION_KEY, so neither the server nor a database dump can show or brute force them.
  # The alphabet leaves out 0, 1, I, L, O, and U, so a code read off paper is not mistyped.
  module RecoveryCodes
    ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ".freeze
    COUNT = 10
    LENGTH = 10
    FORMAT = /\A[#{ALPHABET}]{#{LENGTH}}\z/o

    module_function

    def generate = Array.new(COUNT) { Array.new(LENGTH) { ALPHABET[SecureRandom.random_number(ALPHABET.length)] }.join }

    # As shown and printed: two groups of five.
    def display(code) = "#{code[0, 5]}-#{code[5, 5]}"

    # What an operator typed, without spaces or hyphens, in capitals.
    def normalize(input) = input.to_s.upcase.gsub(/[\s-]/, "")

    def digest(code) = OpenSSL::HMAC.hexdigest("SHA256", Rails.configuration.x.second_factor.recovery_code_key, code)

    # Replaces the factor's codes with new ones; returns them in plaintext, the only time they exist.
    def issue!(factor, now: Time.current)
      codes = generate
      factor.recovery_codes.delete_all
      SecondFactorRecoveryCode.insert_all!(codes.map { |code| { second_factor_id: factor.id, code_digest: digest(code), created_at: now } })
      codes
    end

    # The unused code record matching `input`, or nil. Every unused code is compared in constant time.
    def find_unused(factor, input)
      wanted = digest(normalize(input))
      factor.recovery_codes.unused.to_a.select { |record| ActiveSupport::SecurityUtils.secure_compare(record.code_digest, wanted) }.first
    end
  end
end
