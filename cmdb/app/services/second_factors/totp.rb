module SecondFactors
  # Time-based one-time passwords (RFC 6238 over RFC 4226 HOTP), with the parameters the owner chose (P3-S09, Q26):
  # SHA-1, 6 digits, 30-second steps, which every common authenticator app supports. Small enough to read in full,
  # and tested against the RFC's own vectors (spec/services/second_factors/totp_spec.rb), so no gem is needed.
  module Totp
    DIGITS = 6
    PERIOD = 30 # seconds
    DRIFT = 1 # steps accepted either side of the current one, for phone clocks that are slightly off
    SECRET_BYTES = 20 # 160 bits, the HMAC-SHA1 block size RFC 4226 recommends
    BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".freeze

    module_function

    # A new random key, as the unpadded base32 text that authenticator apps read.
    def generate_secret = base32_encode(SecureRandom.bytes(SECRET_BYTES))

    def step_at(time) = time.to_i / PERIOD

    # RFC 4226 section 5.3: HMAC of the 8-byte big-endian counter, dynamic truncation, then the low digits.
    def code_at_step(secret, step, digits: DIGITS, digest: "SHA1")
      hmac = OpenSSL::HMAC.digest(digest, base32_decode(secret), [ step ].pack("Q>"))
      offset = hmac.getbyte(-1) & 0x0f
      binary = hmac.byteslice(offset, 4).unpack1("N") & 0x7fff_ffff
      (binary % (10**digits)).to_s.rjust(digits, "0")
    end

    # The step whose code equals `code`, among the current step and DRIFT steps either side, or nil. Every candidate
    # is compared in constant time and none is skipped, so the timing does not say which step matched or how close
    # a guess was.
    def matching_step(secret, code, now: Time.current)
      current = step_at(now)
      matched = nil
      (current - DRIFT..current + DRIFT).each do |step|
        matched = step if ActiveSupport::SecurityUtils.secure_compare(code_at_step(secret, step), code.to_s)
      end
      matched
    end

    # otpauth URI for the QR code (the de facto Key Uri Format): the label names this server and the operator.
    def provisioning_uri(secret, account:, issuer: "Fleet CMDB")
      label = ERB::Util.url_encode("#{issuer}:#{account}")
      query = { secret:, issuer:, algorithm: "SHA1", digits: DIGITS, period: PERIOD }.map { |key, value| "#{key}=#{ERB::Util.url_encode(value)}" }
      "otpauth://totp/#{label}?#{query.join('&')}" # %20, not +, for spaces: some apps show a + literally
    end

    # Grouped in fours for typing by hand (the mockup's "EXAM PLEK ...").
    def display_secret(secret) = secret.scan(/.{1,4}/).join(" ")

    def base32_encode(bytes)
      bits = bytes.unpack1("B*")
      bits.scan(/.{1,5}/).map { |chunk| BASE32[chunk.ljust(5, "0").to_i(2)] }.join
    end

    def base32_decode(text)
      bits = text.to_s.upcase.delete("= ").each_char.map do |char|
        index = BASE32.index(char) or raise ArgumentError, "not base32"
        index.to_s(2).rjust(5, "0")
      end.join
      [ bits[0, bits.length / 8 * 8] ].pack("B*")
    end
  end
end
