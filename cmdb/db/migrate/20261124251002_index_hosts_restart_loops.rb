# The fleet list's "Restarted more than N times in the last day" filter (#251, FleetList::RESTART_LOOP) reads the hosts
# whose agent_restart_loop_at, the (limit + 1)th newest restart, is within the window. This partial index holds only the
# hosts that ever had that many restarts, and its column changes only on a heartbeat that shows a restart, so a steady
# heartbeat never touches it, and the filter's page reads only the hosts that loop (review of #307, S1: an index on the
# last restart alone left the loop condition to a filter, and the planner then walked the whole fleet by name). Built
# concurrently, so hosts keep reporting while it builds (as #235's).
#
# Outside a transaction too, the previous migration's check constraints are validated: VALIDATE CONSTRAINT takes
# SHARE UPDATE EXCLUSIVE, so heartbeats keep writing while it scans hosts.
class IndexHostsRestartLoops < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  CHECKS = %w[hosts_agent_restarts_valid hosts_agent_recent_restarts_capped hosts_agent_last_stop_exit_code_valid
              hosts_agent_last_stop_exit_status_valid].freeze

  def change
    add_index :hosts, :agent_restart_loop_at, name: "index_hosts_restart_loops", algorithm: :concurrently,
                                              where: "agent_restart_loop_at IS NOT NULL"
    reversible do |direction|
      direction.up { CHECKS.each { |name| validate_check_constraint :hosts, name: } }
    end
  end
end
