# The replica settings ReplicaReads reads (#198), checked with the other topology settings when config/database.yml
# loads: how long a page waits for the replica to catch up before reading the primary (FLEET_REPLICA_MAX_WAIT_MS), and
# how long a failing replica is skipped (FLEET_REPLICA_SKIP_SECONDS). config.x.replica_may_be_primary is set only by
# config/environments/test.rb: nowhere else may a server that is not in recovery be read as a replica.
Rails.application.config.x.replica_max_wait_ms = DeploymentTopology.replica_max_wait_ms
Rails.application.config.x.replica_skip_seconds = DeploymentTopology.replica_skip_seconds
