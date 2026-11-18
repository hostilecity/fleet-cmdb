# The primary database without the pooler (DIRECT_DATABASE_URL, #198), for SessionLock: a session-level advisory lock
# needs the same server connection from its lock to its unlock, which a transaction-mode pooler does not give. Not a
# subclass of ApplicationRecord, so it never shares the primary's pool. Without the setting it connects to nothing,
# and SessionLock uses the primary's own connection, as before.
class DirectRecord < ActiveRecord::Base
  self.abstract_class = true

  def self.configured? = configurations.configs_for(env_name: Rails.env, name: "direct", include_hidden: true).present?

  connects_to database: { writing: :direct } if configured?
end
