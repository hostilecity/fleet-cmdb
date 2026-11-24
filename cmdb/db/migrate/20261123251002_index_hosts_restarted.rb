# The fleet list's "Restarted more than N times in the last day" filter (#251, FleetList::RESTART_LOOP) starts from the
# hosts whose agent restarted within the window. This partial index holds only hosts that ever reported a restart, and
# its column changes only on a heartbeat that shows one, so a steady heartbeat never touches it. Built concurrently,
# so hosts keep reporting while it builds (as #235's).
#
# Outside a transaction too, the previous migration's check constraints are validated: VALIDATE CONSTRAINT takes
# SHARE UPDATE EXCLUSIVE, so heartbeats keep writing while it scans hosts.
class IndexHostsRestarted < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  CHECKS = %w[hosts_agent_restarts_valid hosts_agent_recent_restarts_capped hosts_agent_last_stop_exit_code_valid
              hosts_agent_last_stop_exit_status_valid].freeze

  def change
    add_index :hosts, :agent_restarted_at, name: "index_hosts_restarted", algorithm: :concurrently,
                                           where: "agent_restarted_at IS NOT NULL"
    reversible do |direction|
      direction.up { CHECKS.each { |name| validate_check_constraint :hosts, name: } }
    end
  end
end
