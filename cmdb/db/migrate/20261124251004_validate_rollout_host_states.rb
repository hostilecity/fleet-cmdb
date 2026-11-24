# Validates the previous migration's rollout_hosts state check outside a transaction (review of #307, S5): VALIDATE
# CONSTRAINT takes SHARE UPDATE EXCLUSIVE, so heartbeats keep reading rollout_hosts (the offer lookup) while it scans.
class ValidateRolloutHostStates < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up = validate_check_constraint :rollout_hosts, name: "rollout_hosts_state_valid"

  def down; end
end
