# Whether recovery mode is set up on the host (#232, ADR 0030): the `units.recovery` of its last heartbeat. NULL when
# the agent does not report it (an older agent), or no heartbeat has come. The heartbeat writes the hosts row only when
# the value changes (Liveness.record_heartbeat!), so a steady fleet leaves it alone.
#
# The partial index serves the fleet list's "Recovery mode: not set up" filter (FleetList), which picks the active hosts
# that have sent a heartbeat and do not report recovery mode as set up. It holds only those hosts, so it shrinks as the
# fleet is covered; its columns change only on enrollment, the first heartbeat, and a change of the value.
class AddAgentUnitsRecoveryToHosts < ActiveRecord::Migration[8.1]
  def change
    add_column :hosts, :agent_units_recovery, :boolean
    add_index :hosts, :id, name: "index_hosts_without_recovery_mode",
                           where: "enrollment_state = 'active' AND first_seen_at IS NOT NULL AND agent_units_recovery IS NOT TRUE"
  end
end
