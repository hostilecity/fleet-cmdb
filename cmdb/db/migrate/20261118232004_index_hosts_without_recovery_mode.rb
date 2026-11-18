# The fleet list's "Recovery mode: not set up" filter (#232, FleetList::WITHOUT_RECOVERY_MODE) picks the active hosts
# that have sent a heartbeat and do not report recovery mode as set up (not set up, not checked, or not reported). This
# partial index holds only those hosts, so it shrinks as the fleet is covered; its columns change only on enrollment,
# the first heartbeat, and a change of the value. Built concurrently, so hosts keep reporting while it builds (review
# of #74, review of #235).
#
# Outside a transaction too, the previous migration's check constraint is validated: VALIDATE CONSTRAINT takes SHARE
# UPDATE EXCLUSIVE, so heartbeats keep writing while it scans hosts (final check of #235).
class IndexHostsWithoutRecoveryMode < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :hosts, :id, name: "index_hosts_without_recovery_mode", algorithm: :concurrently,
                           where: "enrollment_state = 'active' AND first_seen_at IS NOT NULL AND agent_recovery_coverage IS DISTINCT FROM 'set_up'"
    reversible do |direction|
      direction.up { validate_check_constraint :hosts, name: "hosts_agent_recovery_coverage_valid" }
    end
  end
end
