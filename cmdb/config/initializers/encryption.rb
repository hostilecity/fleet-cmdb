# Encryption at rest for operator second-factor secrets (P3-S09, threat model C13). Active Record encryption with
# one key from FLEET_ENCRYPTION_KEY, so a database dump or backup alone does not reveal any TOTP key, and recovery
# codes are stored as HMACs keyed from it, so a dump cannot be brute forced offline either. The key is not
# SECRET_KEY_BASE: changing that signs everyone out but must not destroy every second factor.
#
# Losing or changing FLEET_ENCRYPTION_KEY makes every stored TOTP key and recovery code unusable; each operator is
# then reset with bin/rails second_factor:reset and sets up again (docs/operations/configuration.md).
Rails.application.configure do
  key = ENV["FLEET_ENCRYPTION_KEY"].presence
  key ||= "EXAMPLE-development-and-test-encryption-key-not-secret" unless Rails.env.production?

  config.active_record.encryption.primary_key = key
  # The salt only stretches the key above; it need not be secret, and the key is already random.
  config.active_record.encryption.key_derivation_salt = "fleet-cmdb active record encryption"
  # No deterministic encryption is used: nothing is looked up by an encrypted value.
  config.active_record.encryption.support_unencrypted_data = false

  config.x.second_factor.recovery_code_key = key && ActiveSupport::KeyGenerator.new(key, iterations: 1_000).generate_key("fleet-cmdb recovery codes", 32)

  config.after_initialize do
    next if ENV["SECRET_KEY_BASE_DUMMY"] # the Docker build precompiles assets without runtime settings
    next unless Rails.env.production?

    raise "Set FLEET_ENCRYPTION_KEY (at least 32 characters, for example `openssl rand -hex 32`)" if key.to_s.length < 32
  end
end
