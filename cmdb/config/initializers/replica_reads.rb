# How long a dashboard page waits for the replica to catch up before reading the primary (ReplicaReads, #198):
# FLEET_REPLICA_MAX_WAIT_MS, checked with the other topology settings when config/database.yml loads.
Rails.application.config.x.replica_max_wait_ms = DeploymentTopology.replica_max_wait_ms
