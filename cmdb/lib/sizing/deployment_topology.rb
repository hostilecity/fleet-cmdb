# Optional settings for the scale steps past one VM (#198 steps 2 and 3, docs/operations/scaling.md). All are off by
# default, so one container on one PostgreSQL works as before with nothing new to run. One place for
# config/database.yml, config/application.rb, and the models and controllers that read them.
#
# - FLEET_DB_POOLER: unset (default), or "transaction" when the app's connections go through a transaction-mode
#   pooler such as PgBouncer. The pooled databases then use no prepared statements and no migration advisory lock,
#   because the next transaction may run on another server connection. Needs DIRECT_DATABASE_URL.
# - DIRECT_DATABASE_URL: the primary database, reached without the pooler, for what needs one server connection for a
#   whole run: the session-level advisory locks of the liveness evaluation and of a rollout's stage prepare
#   (SessionLock). Unset, those locks use the primary's own connection, as before.
# - REPLICA_DATABASE_URL: a streaming replica of the primary, read by the dashboard and report pages listed in
#   ReplicaReads, and only once it has caught up. Unset, every page reads the primary.
# - FLEET_REPLICA_MAX_WAIT_MS: how long such a page waits for the replica to catch up before it reads the primary
#   (default 100).
# - FLEET_REPLICA_SKIP_SECONDS: how long a replica that failed, or is not in recovery, is skipped (default 30).
# - FLEET_REPLICA_CONNECT_TIMEOUT_SECONDS: the replica's connect timeout (default 2), so an unreachable replica costs a
#   page at most that before it reads the primary.
# - FLEET_NODE_ROLE: "all" (default), "agent_api" (only the agent hostname), or "dashboard" (only the dashboard
#   hostname, and health on the agent hostname), so the same image can run as either kind of node.
#
# A value outside these stops the boot with a message naming the setting. Plain Ruby, loaded before the application
# by config/application.rb.
module DeploymentTopology
  POOLERS = %w[transaction].freeze
  NODE_ROLES = %w[all agent_api dashboard].freeze
  REPLICA_WAIT_RANGE = (0..2000)
  REPLICA_SKIP_RANGE = (1..3600)
  REPLICA_CONNECT_TIMEOUT_RANGE = (1..60)

  module_function

  # nil (no pooler) or "transaction".
  def pooler(env = ENV)
    value = env["FLEET_DB_POOLER"]
    return nil if value.nil? || value.empty?
    return value if POOLERS.include?(value)

    raise ArgumentError, "FLEET_DB_POOLER must be unset or transaction, not #{value.inspect}"
  end

  def transaction_pooler?(env = ENV) = pooler(env) == "transaction"

  def direct?(env = ENV) = present?(env["DIRECT_DATABASE_URL"])

  def replica?(env = ENV) = present?(env["REPLICA_DATABASE_URL"])

  def replica_max_wait_ms(env = ENV) = whole("FLEET_REPLICA_MAX_WAIT_MS", 100, REPLICA_WAIT_RANGE, env)

  def replica_skip_seconds(env = ENV) = whole("FLEET_REPLICA_SKIP_SECONDS", 30, REPLICA_SKIP_RANGE, env)

  def replica_connect_timeout_seconds(env = ENV) = whole("FLEET_REPLICA_CONNECT_TIMEOUT_SECONDS", 2, REPLICA_CONNECT_TIMEOUT_RANGE, env)

  def node_role(env = ENV)
    value = env.fetch("FLEET_NODE_ROLE", "all")
    return value if NODE_ROLES.include?(value)

    raise ArgumentError, "FLEET_NODE_ROLE must be all, agent_api, or dashboard, not #{value.inspect}"
  end

  # Checks every setting at once, from config/database.yml, so a bad value stops the boot before anything connects.
  # A transaction pooler without a direct connection would run the session-level locks through it, where a lock
  # and its unlock can land on different server connections and the lock stays held.
  def validate!(env = ENV)
    pooler(env)
    replica_max_wait_ms(env)
    replica_skip_seconds(env)
    replica_connect_timeout_seconds(env)
    node_role(env)
    return unless transaction_pooler?(env) && !direct?(env)

    raise ArgumentError, "FLEET_DB_POOLER=transaction needs DIRECT_DATABASE_URL, for the session-level advisory locks"
  end

  def present?(value) = !value.nil? && !value.strip.empty?
  private_class_method :present?

  def whole(name, default, range, env)
    value = env.fetch(name, default.to_s)
    number = value.to_s.match?(/\A\d+\z/) ? value.to_i : -1
    return number if range.cover?(number)

    raise ArgumentError, "#{name} must be a whole number from #{range.min} to #{range.max}, not #{value.inspect}"
  end
  private_class_method :whole
end
