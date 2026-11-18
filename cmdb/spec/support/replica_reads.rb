RSpec.configure do |config|
  # The test replica shares the primary's pool (transactional fixtures), so writes on the reading role are refused
  # only through Rails' prevent_writes, which checks the class the pool is named after. That is ApplicationRecord, the
  # class ReplicaReads switches, when it loads lazily, but ActiveRecord::Base with eager loading (CI). Name it
  # ApplicationRecord in both, so every page ReplicaReads lists runs with writes refused (#198). Production needs
  # none of this: there the reading role has a pool of its own, whose config has replica: true. Rails refuses writes
  # on it (AbstractAdapter#preventing_writes? is true for a replica config, besides the role's prevent_writes), and
  # the standby refuses them itself.
  config.before(:suite) do
    ActiveRecord::Base.connection_pool.pool_config.connection_descriptor = ApplicationRecord
  end

  # ReplicaReads marks the replica down for 30 s after a database error during its check. A spec that breaks the
  # database on purpose would otherwise send every later page in the run to the primary. Each example starts with the
  # replica up.
  config.before { ReplicaReads.reset! }
end
