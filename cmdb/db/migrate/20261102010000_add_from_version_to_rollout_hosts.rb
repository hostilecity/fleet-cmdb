# The agent version a host ran when its stage chose it (P1-D09), so the rollout table and the host's update
# history can show "0.1.0 → 0.2.0". Null for hosts chosen before this column existed.
class AddFromVersionToRolloutHosts < ActiveRecord::Migration[8.1]
  def change
    add_column :rollout_hosts, :from_version, :string, limit: 64
  end
end
