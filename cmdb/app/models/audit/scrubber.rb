module Audit
  # Keeps secrets out of audit before/after values (NFR-1). A key that looks like a secret raises
  # outside production, so the mistake is caught by tests, and is replaced with FILTERED in production,
  # so a missed case can never block an operator or leak the value.
  module Scrubber
    SECRET_KEY = /token|secret|credential|digest|passw|authorization|bearer|api_key|private_key|otp|recovery/i
    FILTERED = "[FILTERED]"

    module_function

    # mode: :raise or :filter.
    def call(value, mode:)
      case value
      when Hash
        value.to_h do |key, sub|
          if key.to_s.match?(SECRET_KEY)
            raise SecretInChangeset, "audit changes must not include #{key.inspect}" if mode == :raise

            [ key.to_s, FILTERED ]
          else
            [ key.to_s, call(sub, mode:) ]
          end
        end
      when Array then value.map { |sub| call(sub, mode:) }
      else value
      end
    end
  end
end
